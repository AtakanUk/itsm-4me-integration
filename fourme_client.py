"""4me REST client for creating requests, built to survive API rate limiting.

* Only 429, 502 and 503 are retried. 504 is not: request creation is not
  idempotent and a gateway timeout may still have created the request.
* ``Retry-After`` is honoured (seconds or HTTP date, capped); otherwise the wait
  uses decorrelated jitter so parallel workers do not retry in lockstep.
* The total time spent retrying is capped, so a SOAR function never hangs.
* A process-wide semaphore limits concurrent calls; SOAR app functions run in
  worker threads and would otherwise hit the rate limit together.
* Every call is written to the audit log, and failures can trigger an alert.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, ClassVar

import requests

import fourme_audit

LOG = logging.getLogger(__name__)

RETRYABLE_STATUS = {429, 502, 503}


@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int = 8
    base_backoff: float = 2.0
    max_backoff: float = 30.0
    retry_after_cap: float = 180.0
    total_budget: float = 300.0


def parse_retry_after(value: str | None, now: dt.datetime | None = None) -> float | None:
    """``Retry-After`` in seconds; supports both the delta-seconds and HTTP-date forms."""
    if value is None or not str(value).strip():
        return None
    value = str(value).strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.UTC)
    now = now or dt.datetime.now(dt.UTC)
    return max(0.0, (when - now).total_seconds())


def compute_backoff(policy: RetryPolicy, retry_after: float | None, previous_sleep: float) -> float:
    """Server-provided ``Retry-After`` wins; otherwise decorrelated jitter."""
    if retry_after is not None:
        return min(retry_after, policy.retry_after_cap)
    low = policy.base_backoff
    high = max(low * 2, previous_sleep * 3)
    return min(policy.max_backoff, random.uniform(low, high))


AlertHook = Callable[[str, str], None]


class FourMeClient:
    _semaphores: ClassVar[dict[int, threading.BoundedSemaphore]] = {}
    _semaphore_lock = threading.Lock()

    def __init__(
        self,
        api_url: str,
        api_token: str,
        account: str,
        account_header: str = "X-Xurrent-Account",
        verify: bool | str = True,
        timeout: tuple[int, int] = (10, 30),
        policy: RetryPolicy | None = None,
        max_concurrent: int = 2,
        alert: AlertHook | None = None,
        db_path: str | None = None,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.api_url = api_url
        self.timeout = timeout
        self.policy = policy or RetryPolicy()
        self.alert = alert
        self.db_path = db_path
        self._sleep = sleep
        self.session = session or requests.Session()
        self.session.verify = verify
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_token}",
                account_header: account,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        with self._semaphore_lock:
            self._semaphore = self._semaphores.setdefault(
                max_concurrent, threading.BoundedSemaphore(max_concurrent)
            )

    # ------------------------------------------------------------------ audit helpers (never fail the call)

    def _audit(self, action: str, *args: Any) -> Any:
        try:
            return getattr(fourme_audit, action)(*args, db_path=self.db_path)
        except Exception as exc:
            LOG.warning("audit %s failed: %s", action, exc)
            return None

    def _alert(self, subject: str, body: str) -> None:
        if self.alert:
            try:
                self.alert(subject, body)
            except Exception as exc:
                LOG.error("Could not send alert '%s': %s", subject, exc)

    # ------------------------------------------------------------------ API

    def create_request(
        self,
        payload: dict[str, Any] | str,
        incident_id: Any = None,
        qradar_id: Any = None,
        existing_record_id: int | None = None,
    ) -> Any:
        """POST a request; returns the parsed response (or text) on success.

        ``existing_record_id`` re-uses an audit row (manual retry) instead of creating one.
        Raises ``requests.HTTPError`` when retries are exhausted or the API rejects the request.
        """
        body = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
        if existing_record_id is not None:
            record_id = existing_record_id
            self._audit("reset_for_retry", record_id)
        else:
            record_id = self._audit("record_attempt", incident_id, qradar_id, self.api_url, body)

        with self._semaphore:
            started = time.monotonic()
            previous_sleep = 0.0
            for attempt in range(1, self.policy.max_retries + 2):
                try:
                    response = self.session.post(
                        self.api_url, data=body.encode("utf-8"), timeout=self.timeout
                    )
                except requests.RequestException as exc:
                    error = f"{type(exc).__name__}: {exc}"
                    if record_id:
                        self._audit("increment_attempt", record_id, None, error)
                        self._audit("mark_failed", record_id, None, None, error)
                    self._alert("[4me] request creation failed", f"Incident {incident_id}: {error}")
                    raise

                if record_id:
                    self._audit("increment_attempt", record_id, response.status_code, None)

                if response.status_code in RETRYABLE_STATUS:
                    retry_after = parse_retry_after(response.headers.get("Retry-After"))
                    wait = compute_backoff(self.policy, retry_after, previous_sleep)
                    elapsed = time.monotonic() - started
                    out_of_budget = elapsed + wait > self.policy.total_budget
                    if attempt <= self.policy.max_retries and not out_of_budget:
                        LOG.warning(
                            "HTTP %s from 4me, attempt %d/%d, sleeping %.1fs (Retry-After=%s)",
                            response.status_code,
                            attempt,
                            self.policy.max_retries,
                            wait,
                            retry_after,
                        )
                        self._sleep(wait)
                        previous_sleep = wait
                        continue
                    reason = (
                        "retry budget exhausted"
                        if out_of_budget
                        else f"{self.policy.max_retries} retries exhausted"
                    )
                    LOG.error("HTTP %s from 4me: %s", response.status_code, reason)
                    if record_id:
                        self._audit(
                            "mark_failed",
                            record_id,
                            response.status_code,
                            response.text,
                            f"{reason}, HTTP {response.status_code}",
                        )
                    # No alert here: the caller decides (e.g. the SOAR function sends one "rate limit" mail).
                    response.raise_for_status()

                if not response.ok:
                    error = f"HTTP {response.status_code}"
                    if record_id:
                        self._audit(
                            "mark_failed", record_id, response.status_code, response.text, error
                        )
                    self._alert(
                        "[4me] request rejected",
                        f"Incident {incident_id}: {error}\n{response.text[:4000]}",
                    )
                    response.raise_for_status()

                try:
                    data: Any = response.json()
                except ValueError:
                    data = response.text
                if record_id:
                    self._audit("mark_success", record_id, response.status_code, data)
                return data
        raise RuntimeError("retry loop ended unexpectedly")  # pragma: no cover


def client_from_env(alert: AlertHook | None = None) -> FourMeClient:
    token = os.environ.get("FOURME_API_TOKEN")
    account = os.environ.get("FOURME_ACCOUNT")
    if not token or not account:
        raise SystemExit("Set FOURME_API_TOKEN and FOURME_ACCOUNT")
    verify_env = os.environ.get("FOURME_VERIFY_SSL", "true")
    verify: bool | str = {"true": True, "false": False}.get(verify_env.lower(), verify_env)
    return FourMeClient(
        api_url=os.environ.get("FOURME_API_URL", "https://api.4me.com/v1/requests"),
        api_token=token,
        account=account,
        account_header=os.environ.get("FOURME_ACCOUNT_HEADER", "X-Xurrent-Account"),
        verify=verify,
        max_concurrent=int(os.environ.get("FOURME_MAX_CONCURRENT", "2")),
        alert=alert,
    )
