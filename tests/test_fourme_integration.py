import datetime as dt
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

import fourme_audit
from escalation import EscalationSettings, build_escalation
from fourme_client import FourMeClient, RetryPolicy, compute_backoff, parse_retry_after
from template_router import build_request_payload, load_rules, route_template

EXAMPLE_RULES = Path(__file__).resolve().parents[1] / "routing_rules.example.json"


def response(status, body="{}", headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.ok = 200 <= status < 300
    resp.text = body
    resp.headers = headers or {}
    resp.json.side_effect = lambda: json.loads(body)
    if not resp.ok:
        resp.raise_for_status.side_effect = requests.HTTPError(f"HTTP {status}", response=resp)
    return resp


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "audit.sqlite3")


TEST_POLICY = RetryPolicy(max_retries=3, total_budget=1000)


def make_client(db, responses, policy=TEST_POLICY):
    session = MagicMock()
    session.headers = {}
    session.post.side_effect = responses
    sleeps = []
    client = FourMeClient(
        "https://api.example.com/v1/requests",
        "token",
        "acct",
        policy=policy,
        db_path=db,
        session=session,
        sleep=sleeps.append,
    )
    return client, session, sleeps


# ------------------------------------------------------------------ retry policy


def test_parse_retry_after_seconds_and_http_date():
    assert parse_retry_after("12") == 12.0
    now = dt.datetime(2026, 4, 28, 10, 0, 0, tzinfo=dt.UTC)
    assert parse_retry_after("Tue, 28 Apr 2026 10:00:30 GMT", now=now) == 30.0
    assert parse_retry_after("garbage") is None and parse_retry_after(None) is None


def test_backoff_honours_retry_after_cap_and_jitter_bounds():
    policy = RetryPolicy()
    assert compute_backoff(policy, 500, 0) == policy.retry_after_cap
    for previous in (0, 5, 50):
        wait = compute_backoff(policy, None, previous)
        assert policy.base_backoff <= wait <= policy.max_backoff


# ------------------------------------------------------------------ client + audit


def test_retries_429_then_succeeds_and_audits_one_row(db):
    client, _session, sleeps = make_client(
        db,
        [response(429, headers={"Retry-After": "3"}), response(503), response(201, '{"id": 77}')],
    )
    assert client.create_request({"subject": "x"}, incident_id=5, qradar_id=9) == {"id": 77}
    assert sleeps[0] == 3.0 and len(sleeps) == 2
    rows = fourme_audit.list_recent(db_path=db)
    assert len(rows) == 1 and rows[0]["status"] == "success" and rows[0]["attempt_count"] == 3


def test_504_is_not_retried(db):
    client, session, sleeps = make_client(db, [response(504, "gateway timeout")])
    with pytest.raises(requests.HTTPError):
        client.create_request({"subject": "x"})
    assert session.post.call_count == 1 and not sleeps
    assert fourme_audit.list_failed(db_path=db)[0]["last_http_status"] == 504


def test_retries_exhausted_marks_failed(db):
    client, session, _ = make_client(db, [response(429)] * 4)
    with pytest.raises(requests.HTTPError):
        client.create_request({"subject": "x"})
    assert session.post.call_count == 4  # first try + 3 retries
    failed = fourme_audit.list_failed(db_path=db)[0]
    assert "retries exhausted" in failed["last_error"]


def test_budget_stops_retrying_early(db):
    policy = RetryPolicy(max_retries=8, total_budget=5)
    client, session, _ = make_client(
        db, [response(429, headers={"Retry-After": "60"})], policy=policy
    )
    with pytest.raises(requests.HTTPError):
        client.create_request({"subject": "x"})
    assert session.post.call_count == 1


def test_manual_retry_reuses_audit_row(db):
    client, _, _ = make_client(db, [response(400, "bad"), response(201, '{"id": 1}')])
    with pytest.raises(requests.HTTPError):
        client.create_request({"subject": "x"}, incident_id=5)
    record_id = fourme_audit.list_failed(db_path=db)[0]["id"]
    client.create_request(
        fourme_audit.get_record(record_id, db_path=db)["payload"], existing_record_id=record_id
    )
    assert len(fourme_audit.list_recent(db_path=db)) == 1
    assert fourme_audit.get_record(record_id, db_path=db)["status"] == "success"
    assert fourme_audit.daily_summary(db_path=db)["success"] == 1


# ------------------------------------------------------------------ escalation + routing


def test_build_escalation_from_incident_and_artifacts():
    incident = {
        "id": 2101,
        "name": "SIEM: Brute force on VPN - 4512",
        "severity_code": "High",
        "discovered_date": 1700000000000,
        "incident_type_ids": ["Malware"],
        "properties": {
            "qradar_id": 4512,
            "describe_the_offense": "Login &amp; lockout",
            "provide_suggestion": "Reset password",
        },
    }
    artifacts = [
        {"type": "IP Address", "value": "192.0.2.10", "description": "QRadar Offense Source"},
        {"type": "QRadar Rule", "value": "VPN brute force"},
        {"type": "QRadar Log Source", "value": "VPN-GW-01"},
        {"type": "QRadar Log Source", "value": "Custom Rule Engine-8 :: qradar"},
    ]
    values = build_escalation(
        incident, artifacts, EscalationSettings(qradar_console="qradar.example.com")
    )
    assert values["qradar_offense_url"].endswith("summaryId=4512")
    assert values["incident_analyst_description"] == "Login & lockout"
    assert values["incident_offense_source"] == "192.0.2.10"
    assert values["incident_triggered_rules"] == "VPN brute force"
    assert values["incident_related_log_sources"] == "VPN-GW-01"


def test_leak_incident_uses_leak_properties():
    incident = {
        "id": 9,
        "name": "Credential leak - IdentityAPI",
        "description": "found",
        "properties": {"qradar_id": None, "compromised_email": "a@example.com"},
    }
    values = build_escalation(incident, [], EscalationSettings(leak_incident_pattern="IdentityAPI"))
    assert values["qradar_id"] == 9 and values["qradar_offense_url"] is None
    assert "Compromised Email: a@example.com" in values["incident_analyst_description"]


def test_routing_rules():
    rules = load_rules(EXAMPLE_RULES)
    assert route_template("[TEST] anything", rules)["skip"] is True
    rule = route_template("RDN - Suspicious Activity: High Level Issue Detected on cloud", rules)
    payload = build_request_payload(
        "Subject", {"qradar_id": 5, "incident_name": "", "other": 1}, rule
    )
    assert payload["custom_fields"] == [{"id": "qradar_id", "value": 5}]
    assert (
        route_template("Something else", rules)["template"] == "your-default-escalation-template-id"
    )
