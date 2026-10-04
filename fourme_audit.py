"""Persistent audit log (SQLite) of every 4me request creation.

One row per request. Retries, both inside the retry loop and manual ones, update
the same row, so the table always shows the latest state of each delivery.
The database path comes from ``FOURME_AUDIT_DB`` (default: ``audit.sqlite3``
next to this file).
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import sqlite3
import threading
from typing import Any

LOG = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.environ.get(
    "FOURME_AUDIT_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit.sqlite3")
)

STATUS_PENDING = "pending"  # sent, no final answer yet
STATUS_SUCCESS = "success"  # 2xx received
STATUS_FAILED = "failed"  # retries exhausted or non-retryable error

SCHEMA = """
CREATE TABLE IF NOT EXISTS api_calls (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id         TEXT,
    qradar_id           TEXT,
    request_url         TEXT NOT NULL,
    payload             TEXT NOT NULL,
    status              TEXT NOT NULL,
    attempt_count       INTEGER NOT NULL DEFAULT 0,
    last_http_status    INTEGER,
    last_response_body  TEXT,
    last_error          TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    success_at          TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_calls_status     ON api_calls(status);
CREATE INDEX IF NOT EXISTS idx_api_calls_incident   ON api_calls(incident_id);
CREATE INDEX IF NOT EXISTS idx_api_calls_created_at ON api_calls(created_at);
"""

# SQLite connections must not be shared between threads; SOAR app functions run in worker threads.
_local = threading.local()
_init_lock = threading.Lock()
_initialized: set[str] = set()


def _now() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _conn(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or DEFAULT_DB_PATH
    cached = getattr(_local, "connections", None)
    if cached is None:
        cached = _local.connections = {}
    if path in cached:
        return cached[path]

    conn = sqlite3.connect(path, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    with _init_lock:
        if path not in _initialized:
            conn.executescript(SCHEMA)
            _initialized.add(path)
    cached[path] = conn
    return conn


def _text(value: Any, limit: int = 8000) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else f"{text[:limit]}...[truncated {len(text) - limit} chars]"


def record_attempt(
    incident_id: Any, qradar_id: Any, request_url: str, payload: str, db_path: str | None = None
) -> int:
    cursor = _conn(db_path).execute(
        """INSERT INTO api_calls (incident_id, qradar_id, request_url, payload, status, attempt_count, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, 0, ?, ?)""",
        (
            None if incident_id is None else str(incident_id),
            None if qradar_id is None else str(qradar_id),
            request_url,
            payload,
            STATUS_PENDING,
            _now(),
            _now(),
        ),
    )
    LOG.info("audit: record %s created for incident %s", cursor.lastrowid, incident_id)
    return int(cursor.lastrowid)


def increment_attempt(
    record_id: int,
    http_status: int | None = None,
    error: str | None = None,
    db_path: str | None = None,
) -> None:
    _conn(db_path).execute(
        """UPDATE api_calls
              SET attempt_count = attempt_count + 1,
                  last_http_status = COALESCE(?, last_http_status),
                  last_error = COALESCE(?, last_error),
                  updated_at = ?
            WHERE id = ?""",
        (http_status, _text(error), _now(), record_id),
    )


def mark_success(
    record_id: int, http_status: int, response_body: Any, db_path: str | None = None
) -> None:
    now = _now()
    _conn(db_path).execute(
        """UPDATE api_calls
              SET status = ?, last_http_status = ?, last_response_body = ?, last_error = NULL, success_at = ?, updated_at = ?
            WHERE id = ?""",
        (STATUS_SUCCESS, http_status, _text(response_body), now, now, record_id),
    )
    LOG.info("audit: record %s succeeded (HTTP %s)", record_id, http_status)


def mark_failed(
    record_id: int,
    http_status: int | None,
    response_body: Any,
    error: str,
    db_path: str | None = None,
) -> None:
    _conn(db_path).execute(
        """UPDATE api_calls
              SET status = ?, last_http_status = ?, last_response_body = ?, last_error = ?, updated_at = ?
            WHERE id = ?""",
        (STATUS_FAILED, http_status, _text(response_body), _text(error), _now(), record_id),
    )
    LOG.info("audit: record %s failed (HTTP %s)", record_id, http_status)


def reset_for_retry(record_id: int, db_path: str | None = None) -> None:
    _conn(db_path).execute(
        "UPDATE api_calls SET status = ?, success_at = NULL, updated_at = ? WHERE id = ?",
        (STATUS_PENDING, _now(), record_id),
    )


def get_record(record_id: int, db_path: str | None = None) -> dict[str, Any] | None:
    row = _conn(db_path).execute("SELECT * FROM api_calls WHERE id = ?", (record_id,)).fetchone()
    return dict(row) if row else None


def list_recent(
    limit: int = 50, status: str | None = None, db_path: str | None = None
) -> list[dict[str, Any]]:
    columns = "id, incident_id, qradar_id, status, attempt_count, last_http_status, last_error, created_at, updated_at, success_at"
    if status:
        rows = (
            _conn(db_path)
            .execute(
                f"SELECT {columns} FROM api_calls WHERE status = ? ORDER BY updated_at DESC LIMIT ?",
                (status, limit),
            )
            .fetchall()
        )
    else:
        rows = (
            _conn(db_path)
            .execute(f"SELECT {columns} FROM api_calls ORDER BY updated_at DESC LIMIT ?", (limit,))
            .fetchall()
        )
    return [dict(row) for row in rows]


def list_failed(limit: int = 100, db_path: str | None = None) -> list[dict[str, Any]]:
    return list_recent(limit=limit, status=STATUS_FAILED, db_path=db_path)


def list_for_date(
    date_iso: str, status: str | None = None, db_path: str | None = None
) -> list[dict[str, Any]]:
    """All rows created on a UTC day (``YYYY-MM-DD``)."""
    if status:
        rows = (
            _conn(db_path)
            .execute(
                "SELECT * FROM api_calls WHERE substr(created_at, 1, 10) = ? AND status = ? ORDER BY id",
                (date_iso, status),
            )
            .fetchall()
        )
    else:
        rows = (
            _conn(db_path)
            .execute(
                "SELECT * FROM api_calls WHERE substr(created_at, 1, 10) = ? ORDER BY id",
                (date_iso,),
            )
            .fetchall()
        )
    return [dict(row) for row in rows]


def daily_summary(date_iso: str | None = None, db_path: str | None = None) -> dict[str, Any]:
    date_iso = date_iso or dt.datetime.now(dt.UTC).strftime("%Y-%m-%d")
    rows = (
        _conn(db_path)
        .execute(
            "SELECT status, COUNT(*) AS n FROM api_calls WHERE substr(created_at, 1, 10) = ? GROUP BY status",
            (date_iso,),
        )
        .fetchall()
    )
    summary: dict[str, Any] = {
        "date": date_iso,
        "success": 0,
        "failed": 0,
        "pending": 0,
        "total": 0,
    }
    for row in rows:
        summary[row["status"]] = row["n"]
        summary["total"] += row["n"]
    return summary
