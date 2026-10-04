"""HTML mail notifications (failure alerts and the daily report)."""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage

LOG = logging.getLogger(__name__)


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def send_html_mail(
    subject: str, html_body: str, to: str | None = None, cc: str | None = None
) -> None:
    """Send through ``SMTP_HOST``; recipients default to ``ALERT_MAIL_TO`` / ``ALERT_MAIL_CC``."""
    recipients = _split(to if to is not None else os.environ.get("ALERT_MAIL_TO", ""))
    copies = _split(cc if cc is not None else os.environ.get("ALERT_MAIL_CC", ""))
    host = os.environ.get("SMTP_HOST")
    if not host or not recipients:
        LOG.warning("SMTP_HOST or recipients not configured; mail '%s' not sent", subject)
        return

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = os.environ.get("MAIL_FROM", "soar@example.com")
    message["To"] = ", ".join(recipients)
    if copies:
        message["Cc"] = ", ".join(copies)
    message.set_content("This message requires an HTML-capable mail client.")
    message.add_alternative(html_body, subtype="html")

    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "25")), timeout=30) as smtp:
        if os.environ.get("SMTP_STARTTLS", "false").lower() == "true":
            smtp.starttls(context=ssl.create_default_context())
        if os.environ.get("SMTP_USERNAME"):
            smtp.login(os.environ["SMTP_USERNAME"], os.environ.get("SMTP_PASSWORD", ""))
        smtp.send_message(message)
    LOG.info("Mail '%s' sent to %s", subject, ", ".join(recipients + copies))


def alert_hook(subject: str, body: str) -> None:
    """Adapter for ``FourMeClient(alert=...)``: plain text body wrapped in <pre>."""
    from html import escape

    send_html_mail(
        subject, f"<html><body><pre style='white-space:pre-wrap'>{escape(body)}</pre></body></html>"
    )
