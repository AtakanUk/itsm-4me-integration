"""SOAR app function ``fourme_escalation``: escalate an incident to 4me.

Function component for an app generated with ``resilient-sdk codegen`` (input:
``incident_id``). Connection settings are read from the environment of the
resilient-circuits service (see ``.env.example``); the routing rules file is
taken from ``FOURME_ROUTING_RULES``.
"""

from __future__ import annotations

import datetime
import html
import os
import traceback

import requests
from resilient_circuits import AppFunctionComponent, FunctionResult, app_function
from resilient_lib import IntegrationError, validate_fields

from escalation import EscalationSettings, build_escalation, fetch_incident
from fourme_client import client_from_env
from notify import alert_hook, send_html_mail
from template_router import build_request_payload, load_rules, route_template

PACKAGE_NAME = "fn_fourme_escalation"
FN_NAME = "fourme_escalation"


def _failure_mail(incident_id, error: Exception) -> None:
    rate_limited = getattr(getattr(error, "response", None), "status_code", None) == 429
    subject = (
        f"[SOAR][4me] Rate limit - retries exhausted for incident {incident_id}"
        if rate_limited
        else f"[SOAR][4me] {type(error).__name__} for incident {incident_id}"
    )
    body = (
        "<html><body>"
        f"<h2 style='color:#c00'>4me escalation failed</h2>"
        f"<p><b>Time:</b> {datetime.datetime.now():%Y-%m-%d %H:%M:%S}<br><b>Incident:</b> {html.escape(str(incident_id))}</p>"
        f"<pre style='white-space:pre-wrap'>{html.escape(traceback.format_exc())}</pre>"
        "</body></html>"
    )
    send_html_mail(subject, body)


class FunctionComponent(AppFunctionComponent):
    def __init__(self, opts):
        super().__init__(opts, PACKAGE_NAME)
        rules_path = os.environ.get("FOURME_ROUTING_RULES", "routing_rules.json")
        self.rules = load_rules(rules_path)
        self.settings = EscalationSettings.from_env()

    @app_function(FN_NAME)
    def _app_function(self, fn_inputs):
        validate_fields(["incident_id"], fn_inputs)
        incident_id = fn_inputs.incident_id
        try:
            incident, artifacts = fetch_incident(self.rest_client(), incident_id)
            values = build_escalation(incident, artifacts, self.settings)
            rule = route_template(values["incident_name"], self.rules)
            if rule is None or rule.get("skip"):
                yield self.status_message(
                    f"No 4me routing rule for '{values['incident_name']}', nothing sent"
                )
                yield FunctionResult({"status": "skipped"})
                return

            payload = build_request_payload(values["incident_name"], values, rule)
            yield self.status_message(f"Creating 4me request with template {rule['template']}")
            response = client_from_env(alert=alert_hook).create_request(
                payload, incident_id=incident_id, qradar_id=values["qradar_id"]
            )
            request_id = response.get("id") if isinstance(response, dict) else None
            yield FunctionResult({"status": "created", "request_id": request_id})
        except (requests.RequestException, IntegrationError, KeyError) as exc:
            _failure_mail(incident_id, exc)
            reason = f"{type(exc).__name__}: {exc}"
            yield FunctionResult({"error": reason}, success=False, reason=reason)
