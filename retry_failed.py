#!/usr/bin/env python3
"""Inspect the audit log and retry failed 4me deliveries.

    python retry_failed.py --list [--status failed|pending|success]
    python retry_failed.py --list-failed
    python retry_failed.py --show 42
    python retry_failed.py --summary [YYYY-MM-DD]
    python retry_failed.py --id 42 [--dry-run]
    python retry_failed.py --all-failed [--dry-run]

A retry re-sends the stored payload and updates the same audit row.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

import fourme_audit


def _brief(row: dict[str, Any]) -> str:
    return (
        f"  id={row['id']:<5} status={row['status']:<8} http={row.get('last_http_status') or '-'!s:<5} "
        f"attempts={row.get('attempt_count', 0):<3} incident={row.get('incident_id') or '-':<10} "
        f"qradar={row.get('qradar_id') or '-':<10} updated={row.get('updated_at')}"
    )


def retry_one(record_id: int, dry_run: bool, client: Any = None) -> bool:
    record = fourme_audit.get_record(record_id)
    if record is None:
        print(f"  [id={record_id}] not found", file=sys.stderr)
        return False
    if record["status"] == fourme_audit.STATUS_SUCCESS:
        print(f"  [id={record_id}] already succeeded, skipped")
        return True
    if not record["payload"]:
        print(f"  [id={record_id}] empty payload, skipped", file=sys.stderr)
        return False

    print(
        f"  [id={record_id}] retrying (incident {record.get('incident_id')}, last HTTP {record.get('last_http_status')})"
    )
    if dry_run:
        print(f"  [id={record_id}] dry run, nothing sent")
        return True
    if client is None:
        from fourme_client import client_from_env

        client = client_from_env()
    try:
        result = client.create_request(
            record["payload"],
            incident_id=record.get("incident_id"),
            qradar_id=record.get("qradar_id"),
            existing_record_id=record_id,
        )
        print(f"  [id={record_id}] OK: {str(result)[:200]}")
        return True
    except Exception as exc:
        print(f"  [id={record_id}] FAILED: {type(exc).__name__}: {exc}")
        return False


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    parser = argparse.ArgumentParser(description="4me audit log viewer and manual retry tool")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--list", action="store_true", help="latest records")
    action.add_argument(
        "--list-failed", action="store_true", help="failed records with their last error"
    )
    action.add_argument("--show", type=int, metavar="ID", help="all fields of one record")
    action.add_argument(
        "--summary", nargs="?", const="today", metavar="YYYY-MM-DD", help="counts for a UTC day"
    )
    action.add_argument("--id", type=int, metavar="ID", help="retry one record")
    action.add_argument("--all-failed", action="store_true", help="retry every failed record")
    parser.add_argument(
        "--status", choices=["pending", "success", "failed"], help="filter for --list"
    )
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument(
        "--dry-run", action="store_true", help="with --id / --all-failed: do not call the API"
    )
    args = parser.parse_args(argv)

    if args.list or args.list_failed:
        rows = fourme_audit.list_recent(args.limit, "failed" if args.list_failed else args.status)
        print(f"{len(rows)} record(s)")
        for row in rows:
            print(_brief(row))
            if args.list_failed and row.get("last_error"):
                print(f"     last_error: {row['last_error']}")
        return 0
    if args.show is not None:
        record = fourme_audit.get_record(args.show)
        if record is None:
            print(f"Record {args.show} not found", file=sys.stderr)
            return 2
        print(json.dumps(record, ensure_ascii=False, indent=2))
        return 0
    if args.summary is not None:
        summary = fourme_audit.daily_summary(None if args.summary == "today" else args.summary)
        print(
            f"{summary['date']}  total={summary['total']}  success={summary['success']}  failed={summary['failed']}  pending={summary['pending']}"
        )
        return 0
    if args.id is not None:
        return 0 if retry_one(args.id, args.dry_run) else 1

    rows = fourme_audit.list_failed(limit=args.limit)
    print(f"Retrying {len(rows)} failed record(s){' (dry run)' if args.dry_run else ''}")
    results = [retry_one(row["id"], args.dry_run) for row in rows]
    print(f"Done: {results.count(True)} ok, {results.count(False)} failed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
