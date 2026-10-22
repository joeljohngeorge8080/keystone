"""Admin plane slice 2 against real PostgreSQL: registry, revocations and the read routes."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import redis
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import Engine

from keystone.admin.app import create_admin_app
from keystone.admin.deps import AdminServices
from keystone.admin.tokens import BOOTSTRAP_PRINCIPAL
from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import PostgresAuditSink
from keystone.broker.revocation import RevocationService
from keystone.broker.service import IdentityContext, IssuanceService
from keystone.db.ids import uuid7
from tests.integration.test_admin_plane import _admin, _auth, _chain
from tests.integration.test_issuance_service_pg import ARN, TEMPLATE, FakeConnector, _decision
from tests.integration.test_revocation_pg import FakeApplier

pytestmark = pytest.mark.integration

ROLE = {"name": "deploy-prod", "role_arn": ARN, "max_ttl_seconds": 1800, "owner": "platform"}


@pytest.fixture
def services(app_engine: Engine, redis_client: redis.Redis) -> AdminServices:
    return _admin(app_engine, redis_client)


@pytest.fixture
def client(services: AdminServices) -> TestClient:
    return TestClient(create_admin_app(services))


def _role_events(engine: Engine) -> list[dict[str, Any]]:
    return [e.details for e in _chain(engine) if e.event_type == EventType.ADMIN_ROLE_CHANGED.value]


def _create_role(client: TestClient) -> None:
    assert client.post("/v1/roles", json=ROLE, headers=_auth()).status_code == 201


# ---- auth on every slice-2 route ----


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/roles"),
        ("POST", "/v1/roles"),
        ("GET", "/v1/roles/deploy-prod"),
        ("PATCH", "/v1/roles/deploy-prod"),
        ("GET", "/v1/roles/deploy-prod/session-policies"),
        ("POST", "/v1/roles/deploy-prod/session-policies"),
        ("POST", "/v1/revocations"),
        ("GET", f"/v1/decisions/{uuid7()}"),
        ("GET", "/v1/audit/events"),
        ("GET", "/v1/audit/verify"),
        ("GET", "/v1/issuances"),
    ],
)
def test_every_route_requires_an_admin_bearer(client: TestClient, method: str, path: str) -> None:
    response = client.request(method, path, json={})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "ADMIN_TOKEN_INVALID"


# ---- roles ----


def test_role_lifecycle_is_audited(client: TestClient, app_engine: Engine) -> None:
    created = client.post("/v1/roles", json=ROLE, headers=_auth())
    assert created.status_code == 201, created.text
    assert created.json()["enabled"] is True and created.json()["owner"] == "platform"

    listed = client.get("/v1/roles", headers=_auth()).json()["roles"]
    assert [r["name"] for r in listed] == ["deploy-prod"]

    patched = client.patch(
        "/v1/roles/deploy-prod",
        json={"enabled": False, "description": "frozen during incident"},
        headers=_auth(),
    )
    assert patched.status_code == 200
    assert patched.json()["enabled"] is False
    assert patched.json()["max_ttl_seconds"] == 1800  # untouched fields keep their values
    noop = client.patch("/v1/roles/deploy-prod", json={"enabled": False}, headers=_auth())
    assert noop.status_code == 200

    events = _role_events(app_engine)
    assert [e["data"]["action"] for e in events] == ["role_created", "role_updated"]
    assert events[1]["data"]["changes"] == {
        "enabled": {"from": True, "to": False},
        "description": {"from": "", "to": "frozen during incident"},
    }
    assert all(e["actor"] == BOOTSTRAP_PRINCIPAL and e["admin_principal_id"] for e in events)


def test_role_create_and_patch_validation(client: TestClient) -> None:
    _create_role(client)
    duplicate = client.post("/v1/roles", json={**ROLE, "name": "other"}, headers=_auth())
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "REGISTRY_ROLE_EXISTS"
    for body in (
        {**ROLE, "role_arn": "arn:aws:iam::1:user/x"},
        {**ROLE, "max_ttl_seconds": 7200},
        {**ROLE, "name": "Deploy_Prod"},
    ):
        assert client.post("/v1/roles", json=body, headers=_auth()).status_code == 400
    retarget = client.patch(
        "/v1/roles/deploy-prod",
        json={"role_arn": ARN.replace("prod", "evil")},
        headers=_auth(),
    )
    assert retarget.status_code == 400  # role_arn is not patchable
    missing = client.get("/v1/roles/nope", headers=_auth())
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "REGISTRY_ROLE_UNKNOWN"
    assert client.get("/v1/roles/Not_A_Name", headers=_auth()).status_code == 400


# ---- session-policy templates ----


def test_templates_are_validated_and_audited(client: TestClient, app_engine: Engine) -> None:
    _create_role(client)
    path = "/v1/roles/deploy-prod/session-policies"
    added = client.post(
        path, json={"ref": "s3-deploy-narrow", "policy_document": TEMPLATE}, headers=_auth()
    )
    assert added.status_code == 201, added.text
    again = client.post(
        path, json={"ref": "s3-deploy-narrow", "policy_document": TEMPLATE}, headers=_auth()
    )
    assert again.status_code == 409 and again.json()["error"]["code"] == "TEMPLATE_EXISTS"
    no_statement = client.post(
        path, json={"ref": "empty", "policy_document": {"Version": "2012-10-17"}}, headers=_auth()
    )
    assert no_statement.status_code == 400
    assert no_statement.json()["error"]["code"] == "TEMPLATE_INVALID"
    huge = {"Version": "2012-10-17", "Statement": [{"Sid": "x" * 2100}]}
    too_big = client.post(path, json={"ref": "huge", "policy_document": huge}, headers=_auth())
    assert too_big.status_code == 400 and too_big.json()["error"]["code"] == "TEMPLATE_INVALID"
    unknown = client.post(
        "/v1/roles/nope/session-policies",
        json={"ref": "x1", "policy_document": TEMPLATE},
        headers=_auth(),
    )
    assert unknown.status_code == 404

    listed = client.get(path, headers=_auth()).json()["session_policies"]
    assert [t["ref"] for t in listed] == ["s3-deploy-narrow"]
    detail = client.get("/v1/roles/deploy-prod", headers=_auth()).json()
    assert detail["session_policies"][0]["policy_document"] == TEMPLATE
    assert [e["data"]["action"] for e in _role_events(app_engine)] == [
        "role_created",
        "template_added",
    ]


# ---- revocations ----


def test_revocation_defaults_to_the_runbook_document(
    client: TestClient, app_engine: Engine
) -> None:
    _create_role(client)
    client.patch("/v1/roles/deploy-prod", json={"enabled": False}, headers=_auth())
    response = client.post("/v1/revocations", json={"role": "deploy-prod"}, headers=_auth())
    assert response.status_code == 201, response.text  # a disabled role stays revocable
    body = response.json()
    assert body["applied"] is False and body["policy_name"] is None
    statement = body["rendered_policy"]["Statement"][0]
    assert statement["Effect"] == "Deny"
    flagged = [e for e in _chain(app_engine) if e.event_type == "revocation_flagged"]
    assert flagged[0].details["admin_principal_id"] is not None


def test_revocation_applied_and_unconfirmed(services: AdminServices, app_engine: Engine) -> None:
    def client_with(applier: FakeApplier) -> TestClient:
        revocations = RevocationService(app_engine, PostgresAuditSink(), applier)
        return TestClient(create_admin_app(dataclasses.replace(services, revocations=revocations)))

    applied_client = client_with(FakeApplier(enabled=True))
    _create_role(applied_client)
    not_before = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    applied = applied_client.post(
        "/v1/revocations", json={"role": "deploy-prod", "not_before": not_before}, headers=_auth()
    )
    assert applied.status_code == 201 and applied.json()["applied"] is True
    applied_events = [e for e in _chain(app_engine) if e.event_type == "revocation_applied"]
    assert applied_events[0].details["admin_principal_id"] is not None

    unconfirmed = client_with(FakeApplier(enabled=True, confirm=False)).post(
        "/v1/revocations", json={"role": "deploy-prod"}, headers=_auth()
    )
    assert unconfirmed.status_code == 502
    assert unconfirmed.json()["error"]["code"] == "REVOCATION_UNCONFIRMED"


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"role": "nope"}, 404),
        ({"role": "deploy-prod", "not_before": "2026-10-22T10:00:00"}, 400),  # naive
        ({"role": "deploy-prod", "not_before": "2999-01-01T00:00:00Z"}, 400),  # future
        ({"role": "deploy-prod", "not_before": "yesterday"}, 400),
    ],
)
def test_revocation_validation(client: TestClient, body: dict[str, Any], status: int) -> None:
    _create_role(client)
    assert client.post("/v1/revocations", json=body, headers=_auth()).status_code == status


# ---- read routes ----


@pytest.fixture
def issued(client: TestClient, app_engine: Engine) -> list[str]:
    """Two allowed decisions chained like the authz stage does, each followed by an issuance."""
    _create_role(client)
    client.post(
        "/v1/roles/deploy-prod/session-policies",
        json={"ref": "s3-deploy-narrow", "policy_document": TEMPLATE},
        headers=_auth(),
    )
    pin_id = uuid7()
    with app_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO policy_pins (id, bundle_digest, bundle_sequence, active) "
                "VALUES (:id, :digest, 1, true)"
            ),
            {"id": pin_id, "digest": "sha256:" + "cd" * 32},
        )
    sink = PostgresAuditSink()
    issuer = IssuanceService(app_engine, sink, FakeConnector())
    decision_ids = []
    for n in range(2):
        decision = _decision(pin_id)
        with app_engine.begin() as conn:
            seq = sink.append(
                conn,
                AuditEventInput(
                    event_type=EventType.DECISION_ALLOWED,
                    occurred_at=datetime.now(UTC),
                    actor="octocat",
                    data={"decision_id": str(decision.decision_id), "grant": "deploy-prod"},
                ),
            ).seq
        identity = IdentityContext(
            jti_hash=bytes([n]) * 32,
            actor="octocat",
            repository="acme/app",
            repository_id="42",
            run_id=str(1000 + n),
            ref="refs/heads/main",
            workflow_ref="acme/app/.github/workflows/deploy.yml@refs/heads/main",
            claims={
                "repository": "acme/app",
                "ref": "refs/heads/main",
                "actor": "octocat",
                "run_id": str(1000 + n),
            },
        )
        issuer.issue(decision.model_copy(update={"decision_audit_seq": seq}), identity, 900)
        decision_ids.append(str(decision.decision_id))
    return decision_ids


def test_decision_detail_joins_the_issuance_outcome(client: TestClient, issued: list[str]) -> None:
    response = client.get(f"/v1/decisions/{issued[0]}", headers=_auth())
    assert response.status_code == 200
    events = response.json()["events"]
    assert [e["event_type"] for e in events] == ["decision_allowed", "credential_issued"]
    # Rendered from the hashed canonical bytes (R1), with both hashes.
    assert events[0]["event"]["data"]["decision_id"] == issued[0]
    assert len(events[0]["event_hash"]) == 64 and len(events[0]["prev_hash"]) == 64
    assert "never-stored" not in response.text
    assert client.get(f"/v1/decisions/{uuid7()}", headers=_auth()).status_code == 404
    assert client.get("/v1/decisions/not-a-uuid", headers=_auth()).status_code == 400


def test_audit_events_keyset_pagination_and_filter(
    client: TestClient, issued: list[str], app_engine: Engine
) -> None:
    total = len(_chain(app_engine))
    seen: list[int] = []
    after = 0
    while True:
        page = client.get(f"/v1/audit/events?after_seq={after}&limit=3", headers=_auth()).json()
        seen.extend(e["seq"] for e in page["events"])
        if page["next_after_seq"] is None:
            break
        after = page["next_after_seq"]
    assert seen == list(range(1, total + 1))
    filtered = client.get("/v1/audit/events?event_type=credential_issued", headers=_auth()).json()
    assert [e["event_type"] for e in filtered["events"]] == ["credential_issued"] * 2
    bad = client.get("/v1/audit/events?event_type=nonsense", headers=_auth())
    assert bad.status_code == 400


def test_audit_verify_online(client: TestClient, issued: list[str], app_engine: Engine) -> None:
    result = client.get("/v1/audit/verify", headers=_auth()).json()
    total = len(_chain(app_engine))
    assert result["ok"] is True and result["complete"] is True
    assert result["events_verified"] == total == result["head_seq"]
    partial = client.get("/v1/audit/verify?from_seq=2&to_seq=3", headers=_auth()).json()
    assert partial["ok"] is True and partial["events_verified"] == 2
    assert partial["complete"] is False
    beyond = client.get(f"/v1/audit/verify?from_seq={total + 5}", headers=_auth())
    assert beyond.status_code == 400


def test_issuances_newest_first_with_keyset(client: TestClient, issued: list[str]) -> None:
    first = client.get("/v1/issuances?limit=1", headers=_auth()).json()
    assert len(first["issuances"]) == 1 and first["next_before"] is not None
    second = client.get(
        f"/v1/issuances?limit=1&before={first['next_before']}", headers=_auth()
    ).json()
    newest, older = first["issuances"][0], second["issuances"][0]
    assert newest["id"] > older["id"] and newest["run_id"] == "1001"
    assert newest["state"] == "issued" and newest["repository"] == "acme/app"
    assert "jti_hash" not in newest and "identity_claims" not in newest
    delivered = client.get("/v1/issuances?state=delivered", headers=_auth()).json()
    assert delivered["issuances"] == []
    assert client.get("/v1/issuances?state=bogus", headers=_auth()).status_code == 400


def test_display_comes_from_hashed_bytes_and_tamper_is_reported(
    client: TestClient, issued: list[str], admin_engine: Engine
) -> None:
    # R1: an attacker who rewrites the `details` projection (as a DB owner could, with the
    # append-only trigger off) must not change what operators see, and verify must flag it.
    with admin_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_rewrite"))
        conn.execute(
            text(
                "UPDATE audit_events SET details = jsonb_set(details, '{actor}', '\"mallory\"') "
                "WHERE seq = 1"
            )
        )
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_rewrite"))
    first = client.get("/v1/audit/events?limit=1", headers=_auth()).json()["events"][0]
    assert first["event"]["actor"] == "system:bootstrap"  # the bootstrap token event
    assert "mallory" not in client.get("/v1/audit/events", headers=_auth()).text
    result = client.get("/v1/audit/verify", headers=_auth()).json()
    assert result["ok"] is False and result["finding"]["seq"] == 1
