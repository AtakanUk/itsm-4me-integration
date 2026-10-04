#!/usr/bin/env python3
"""Daily mail report of 4me deliveries (counts plus the failed and pending records).

    python daily_report.py                     # today (UTC)
    python daily_report.py --date 2026-04-28
    python daily_report.py --dry-run           # print the HTML instead of mailing it
    python daily_report.py --skip-empty        # no mail on days without traffic

Crontab: ``55 23 * * * cd /opt/itsm-4me && .venv/bin/python daily_report.py --skip-empty``
"""

from __future__ import annotations

import argparse
import datetime
import html
import logging
import os
import sys
from typing import Any

import fourme_audit


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _records_table(records: list[dict[str, Any]], title: str, color: str) -> str:
    if not records:
        return f"<p style='margin-top:14px'><b>{title}:</b> none.</p>"
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{_esc(r.get(key))}</td>"
            for key in (
                "id",
                "incident_id",
                "qradar_id",
                "last_http_status",
                "attempt_count",
                "created_at",
                "updated_at",
            )
        )
        + f"<td><pre style='margin:0;white-space:pre-wrap;font-size:11px'>{_esc((r.get('last_error') or '')[:500])}</pre></td>"
        + "</tr>"
        for r in records
    )
    headers = "".join(
        f"<th>{h}</th>"
        for h in (
            "id",
            "incident",
            "offense",
            "http",
            "attempts",
            "created",
            "updated",
            "last error",
        )
    )
    return (
        f"<h3 style='color:{color};margin:18px 0 6px'>{title} ({len(records)})</h3>"
        f"<table cellpadding='6' style='border-collapse:collapse;border:1px solid #ccc;font-size:12px'>"
        f"<tr style='background:#f0f0f0'>{headers}</tr>{rows}</table>"
    )


def build_report(date_iso: str, summary: dict[str, Any], records: list[dict[str, Any]]) -> str:
    failed = [r for r in records if r["status"] == fourme_audit.STATUS_FAILED]
    pending = [r for r in records if r["status"] == fourme_audit.STATUS_PENDING]
    return (
        "<html><body style='font-family:Arial,Helvetica,sans-serif;color:#222'>"
        "<h2>4me Integration - Daily Report</h2>"
        f"<p>Request deliveries on <b>{_esc(date_iso)}</b> (UTC).</p>"
        "<table cellpadding='8' style='border-collapse:collapse;border:1px solid #ccc'>"
        "<tr style='background:#f0f0f0'><th>Total</th><th>Succeeded</th><th>Failed</th><th>Pending</th></tr>"
        f"<tr><td align='right'>{summary['total']}</td><td align='right' style='color:#080'>{summary['success']}</td>"
        f"<td align='right' style='color:#c00'><b>{summary['failed']}</b></td><td align='right' style='color:#c80'>{summary['pending']}</td></tr>"
        "</table>"
        + _records_table(failed, "Failed", "#c00")
        + _records_table(pending, "Pending (no final answer)", "#c80")
        + "<p style='margin-top:22px;color:#666;font-size:11px'>Manual handling on the integration host: "
        "<code>python retry_failed.py --show &lt;id&gt;</code>, <code>--id &lt;id&gt;</code>, <code>--all-failed</code></p>"
        "</body></html>"
    )


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    parser = argparse.ArgumentParser(description="Daily 4me delivery report")
    parser.add_argument("--date", default=datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d"))
    parser.add_argument(
        "--to",
        default=os.environ.get("REPORT_MAIL_TO"),
        help="comma-separated recipients (default: REPORT_MAIL_TO)",
    )
    parser.add_argument("--cc", default=os.environ.get("REPORT_MAIL_CC", ""))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-empty", action="store_true")
    args = parser.parse_args(argv)

    summary = fourme_audit.daily_summary(args.date)
    if args.skip_empty and summary["total"] == 0:
        print(f"[{args.date}] no deliveries, report not sent")
        return 0

    body = build_report(args.date, summary, fourme_audit.list_for_date(args.date))
    subject = (
        f"[4me] Daily report {args.date} - total {summary['total']} / ok {summary['success']} / "
        f"failed {summary['failed']} / pending {summary['pending']}"
    )
    if args.dry_run:
        print(f"Subject: {subject}\n\n{body}")
        return 0
    if not args.to:
        print("No recipients: set REPORT_MAIL_TO or use --to", file=sys.stderr)
        return 2

    from notify import send_html_mail

    send_html_mail(subject, body, to=args.to, cc=args.cc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
