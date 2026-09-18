"""Revocation ordering (F6): flagged -> applied -> confirmed -> revocation_applied, never earlier."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import quote

import boto3
import pytest
from botocore.stub import Stubber
from sqlalchemy import text
from sqlalchemy.engine import Engine

from keystone.audit.events import EventType
from keystone.audit.sink import PostgresAuditSink
from keystone.audit.store import load_events, snapshot_head
from keystone.broker.revocation import (
    IamDenyPolicyApplier,
    RevocationNotEnabled,
    RevocationService,
    RevocationUnconfirmed,
    policy_name_for,
    render_deny_policy,
)
from keystone.registry.repo import RegistryError, RoleRegistry

pytestmark = pytest.mark.integration

ARN = "arn:aws:iam::123456789012:role/keystone-deploy-prod"
NOT_BEFORE = datetime(2026, 9, 19, 12, 30, 0, tzinfo=UTC)


class FakeApplier:
    def __init__(self, *, enabled: bool, confirm: bool = True) -> None:
        self.enabled = enabled
        self.confirm_result = confirm
        self.applied: list[tuple[str, datetime]] = []

    def apply(self, role_arn: str, not_before: datetime) -> str:
        if not self.enabled:
            raise RevocationNotEnabled(render_deny_policy(not_before))
        self.applied.append((role_arn, not_before))
        return policy_name_for(not_before)

    def confirm(self, role_arn: str, policy_name: str, not_before: datetime) -> bool:
        return self.confirm_result


@pytest.fixture
def role(app_engine: Engine) -> None:
    with app_engine.begin() as conn:
        RoleRegistry(conn).register_role(name="deploy-prod", role_arn=ARN, max_ttl_seconds=900)


def _types(engine: Engine) -> list[str]:
    with engine.connect() as conn:
        head = snapshot_head(conn)
        return [e.event_type for e in load_events(conn, 1, head.seq)]


def _row(engine: Engine) -> tuple[str, str, str | None]:
    with engine.connect() as conn:
        row = conn.execute(text("SELECT mechanism, state, policy_name FROM revocations")).one()
    return row.mechanism, row.state, row.policy_name


def test_mechanism_3_off_by_default_renders_the_runbook_policy(
    app_engine: Engine, role: None
) -> None:
    service = RevocationService(app_engine, PostgresAuditSink(), FakeApplier(enabled=False))
    result = service.revoke_role("deploy-prod", not_before=NOT_BEFORE, actor="admin:alice")
    assert result.applied is False and result.policy_name is None
    assert result.rendered_policy == render_deny_policy(NOT_BEFORE)
    assert result.rendered_policy["Statement"][0]["Condition"] == {
        "DateLessThan": {"aws:TokenIssueTime": "2026-09-19T12:30:00Z"}
    }
    assert _row(app_engine) == ("runbook", "flagged", None)
    assert _types(app_engine) == [EventType.REVOCATION_FLAGGED.value]


def test_enabled_applies_confirms_then_writes_applied(app_engine: Engine, role: None) -> None:
    applier = FakeApplier(enabled=True)
    service = RevocationService(app_engine, PostgresAuditSink(), applier)
    result = service.revoke_role("deploy-prod", not_before=NOT_BEFORE, actor="admin:alice")
    assert result.applied is True and result.policy_name == policy_name_for(NOT_BEFORE)
    assert applier.applied == [(ARN, NOT_BEFORE)]
    assert _row(app_engine) == ("iam_deny_policy", "applied", policy_name_for(NOT_BEFORE))
    assert _types(app_engine) == [
        EventType.REVOCATION_FLAGGED.value,
        EventType.REVOCATION_APPLIED.value,
    ]


def test_unconfirmed_never_claims_applied_and_reconciler_backfills(
    app_engine: Engine, role: None
) -> None:
    applier = FakeApplier(enabled=True, confirm=False)
    service = RevocationService(app_engine, PostgresAuditSink(), applier)
    with pytest.raises(RevocationUnconfirmed):
        service.revoke_role("deploy-prod", not_before=NOT_BEFORE, actor="admin:alice")
    assert _row(app_engine)[1] == "flagged"
    assert _types(app_engine) == [EventType.REVOCATION_FLAGGED.value]

    assert service.reconcile_open() == 0  # IAM still does not show it: nothing claimed
    applier.confirm_result = True  # IAM now reads back the deny policy (reverse-crash case)
    assert service.reconcile_open() == 1
    assert _row(app_engine)[1] == "applied"
    assert _types(app_engine)[-1] == EventType.REVOCATION_APPLIED.value
    assert service.reconcile_open() == 0  # idempotent


def test_unknown_or_disabled_role_is_refused_before_flagging(
    app_engine: Engine, role: None
) -> None:
    service = RevocationService(app_engine, PostgresAuditSink(), FakeApplier(enabled=True))
    with pytest.raises(RegistryError):
        service.revoke_role("nope", not_before=NOT_BEFORE, actor="a")
    with app_engine.begin() as conn:
        RoleRegistry(conn).set_role_enabled("deploy-prod", False)
    with pytest.raises(RegistryError):
        service.revoke_role("deploy-prod", not_before=NOT_BEFORE, actor="a")
    assert _types(app_engine) == []


def test_iam_applier_request_shape_and_read_back() -> None:
    client = boto3.client(
        "iam", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y"
    )
    stubber = Stubber(client)
    name = policy_name_for(NOT_BEFORE)
    document = json.dumps(render_deny_policy(NOT_BEFORE), separators=(",", ":"))
    stubber.add_response(
        "put_role_policy",
        {},
        expected_params={
            "RoleName": "keystone-deploy-prod",
            "PolicyName": name,
            "PolicyDocument": document,
        },
    )
    stubber.add_response(
        "get_role_policy",
        {"RoleName": "keystone-deploy-prod", "PolicyName": name, "PolicyDocument": quote(document)},
    )
    stubber.add_response(
        "get_role_policy",
        {
            "RoleName": "keystone-deploy-prod",
            "PolicyName": name,
            "PolicyDocument": quote('{"Version":"2012-10-17","Statement":[]}'),
        },
    )
    stubber.add_client_error(
        "get_role_policy", service_error_code="NoSuchEntity", http_status_code=404
    )
    stubber.activate()

    applier = IamDenyPolicyApplier(client, enabled=True)
    assert applier.apply(ARN, NOT_BEFORE) == name
    assert applier.confirm(ARN, name, NOT_BEFORE) is True
    assert applier.confirm(ARN, name, NOT_BEFORE) is False  # different document read back
    assert applier.confirm(ARN, name, NOT_BEFORE) is False  # policy absent
    stubber.assert_no_pending_responses()

    with pytest.raises(RevocationNotEnabled):
        IamDenyPolicyApplier(client, enabled=False).apply(ARN, NOT_BEFORE)
