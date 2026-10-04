"""Builds the SOC escalation data for a SOAR incident.

The analyst writes the analysis into two incident fields (offense description
and suggestion); the related QRadar rules, log sources and the offense source are
collected from the incident's artifacts. Credential-leak incidents coming from a
threat-intel feed have no QRadar offense, so their description is assembled from
the leak properties instead.
"""

from __future__ import annotations

import datetime as dt
import html
import os
from dataclasses import dataclass, field
from typing import Any

LEAK_FIELDS = (
    ("Compromised Email", "compromised_email"),
    ("Exposed Secret", "exposed_secret"),
    ("First Downloaded", "first_downloaded"),
    ("Latest Downloaded", "latest_downloaded"),
    ("Leak Source", "leak_source"),
    ("Exfiltration Date", "exfiltration_date"),
    ("Operating System", "operating_system"),
    ("OS Username", "os_username"),
    ("Malware File", "malware_file"),
    ("Computer Name", "computer_name"),
    ("IP Address", "ip_address"),
    ("Auth Domain", "auth_domain"),
    ("Malware Family", "malware_family"),
)


@dataclass(frozen=True)
class EscalationSettings:
    qradar_console: str | None = None
    rule_artifact_type: str = "QRadar Rule"
    log_source_artifact_type: str = "QRadar Log Source"
    offense_source_marker: str = "QRadar Offense Source"
    leak_incident_pattern: str | None = None
    description_field: str = "describe_the_offense"
    suggestion_field: str = "provide_suggestion"
    excluded_log_sources: tuple[str, ...] = field(default=("Custom Rule Engine",))

    @classmethod
    def from_env(cls) -> EscalationSettings:
        return cls(
            qradar_console=os.environ.get("QRADAR_CONSOLE") or None,
            rule_artifact_type=os.environ.get(
                "ESCALATION_RULE_ARTIFACT_TYPE", cls.rule_artifact_type
            ),
            log_source_artifact_type=os.environ.get(
                "ESCALATION_LOG_SOURCE_ARTIFACT_TYPE", cls.log_source_artifact_type
            ),
            leak_incident_pattern=os.environ.get("ESCALATION_LEAK_INCIDENT_PATTERN") or None,
        )


def _format_ms(value: Any) -> str | None:
    if not value:
        return None
    return dt.datetime.fromtimestamp(int(value) / 1000).strftime("%d-%m-%Y %H:%M:%S")


def _artifact_type(artifact: dict[str, Any]) -> str:
    # With handle_format=names the type is a name; otherwise a numeric ID.
    return str(artifact.get("type"))


def offense_url(console: str | None, offense_id: Any) -> str | None:
    if not console or offense_id in (None, ""):
        return None
    return f"https://{console}/console/qradar/jsp/QRadar.jsp?appName=Sem&pageId=OffenseSummary&summaryId={offense_id}"


def build_escalation(
    incident: dict[str, Any], artifacts: list[dict[str, Any]], settings: EscalationSettings
) -> dict[str, Any]:
    properties = incident.get("properties") or {}
    name = incident.get("name") or ""
    is_leak = bool(settings.leak_incident_pattern and settings.leak_incident_pattern in name)

    qradar_id = properties.get("qradar_id")
    url = offense_url(settings.qradar_console, qradar_id)
    if qradar_id is None:
        # Incidents without an offense: fall back to the source system's resource ID.
        qradar_id = incident.get("id") if is_leak else properties.get("resource_id")

    if is_leak:
        lines = [f"{label}: {properties.get(key)}" for label, key in LEAK_FIELDS[:5]]
        lines.append(f"Description: {incident.get('description')}")
        lines += [f"{label}: {properties.get(key)}" for label, key in LEAK_FIELDS[5:]]
        description, suggestion = "\n".join(lines), ""
    else:
        description = html.unescape(properties.get(settings.description_field) or "")
        suggestion = html.unescape(properties.get(settings.suggestion_field) or "")

    offense_source = ""
    rules: list[str] = []
    log_sources: list[str] = []
    for artifact in artifacts:
        value = artifact.get("value") or ""
        if settings.offense_source_marker in str(artifact.get("description") or ""):
            offense_source = value
        artifact_type = _artifact_type(artifact)
        if artifact_type == settings.rule_artifact_type:
            rules.append(value)
        elif artifact_type == settings.log_source_artifact_type and not any(
            excluded in value for excluded in settings.excluded_log_sources
        ):
            log_sources.append(value)

    incident_types = incident.get("incident_type_ids") or [None]
    return {
        "incident_id": incident.get("id"),
        "qradar_id": qradar_id,
        "qradar_offense_url": url,
        "incident_name": name,
        "incident_severity_code": incident.get("severity_code"),
        "incident_analyst_description": description,
        "incident_analyst_suggestion": suggestion,
        "incident_date_reported": _format_ms(properties.get("date_reported")),
        "incident_discovered_time": _format_ms(incident.get("discovered_date")),
        "incident_type": incident_types[0],
        "incident_related_log_sources": "<br>".join(log_sources),
        "incident_offense_source": offense_source,
        "incident_triggered_rules": "<br>".join(rules),
    }


def fetch_incident(
    rest_client: Any, incident_id: Any
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Incident (with select values as names) and its artifacts."""
    incident = rest_client.get(f"/incidents/{incident_id}?handle_format=names")
    artifacts = rest_client.get(f"/incidents/{incident_id}/artifacts?handle_format=names")
    return incident, artifacts
