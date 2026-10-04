"""Rule-based routing of SOAR incidents to 4me request templates.

Each rule matches a substring of the incident name (case-insensitive) and says
which 4me template and service instance to use, and which values to send as
custom fields. Rules are evaluated in order; ``"skip": true`` drops matching
incidents (e.g. test rules).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_rules(path: str | Path) -> list[dict[str, Any]]:
    rules = json.loads(Path(path).read_text(encoding="utf-8"))
    for index, rule in enumerate(rules):
        if "contains" not in rule:
            raise ValueError(f"rule #{index} has no 'contains'")
        if not rule.get("skip") and not {"template", "service_instance_id"} <= rule.keys():
            raise ValueError(
                f"rule '{rule['contains']}' needs 'template' and 'service_instance_id'"
            )
    return rules


def route_template(incident_name: str, rules: list[dict[str, Any]]) -> dict[str, Any] | None:
    name = incident_name.lower()
    return next((rule for rule in rules if str(rule["contains"]).lower() in name), None)


def build_request_payload(
    incident_name: str, values: dict[str, Any], rule: dict[str, Any]
) -> dict[str, Any]:
    """4me request for ``rule``; ``rule["fields"]`` limits and orders the custom fields."""
    wanted = rule.get("fields") or list(values)
    custom_fields = [
        {"id": name, "value": values[name]} for name in wanted if values.get(name) not in (None, "")
    ]
    return {
        "subject": incident_name[:255],
        "impact": rule.get("impact", "low"),
        "template": str(rule["template"]),
        "service_instance_id": str(rule["service_instance_id"]),
        "custom_fields": custom_fields,
    }
