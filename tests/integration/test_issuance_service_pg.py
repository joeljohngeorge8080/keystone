"""IssuanceService against real PostgreSQL with a fake connector: ordering, states, audit."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import JsonValue
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import PostgresAuditSink
from keystone.audit.store import load_events, snapshot_head
from keystone.audit.verify import StoredEvent, verify_chain
from keystone.broker.connectors.base import (
    AccessDeniedError,
    ConnectorCapabilities,
    IndeterminateError,
    IssuedCredential,
    MintRequest,
)
from keystone.broker.issuance import IllegalTransition, IssuanceRepository, IssuanceState
from keystone.broker.service import (
    AuthorizedDecision,
    IdentityContext,
    IssuanceService,
    PolicyRegistryDivergence,
    TtlDenied,
)
from keystone.db.ids import uuid7
from keystone.registry.repo import RegistryError, RoleRegistry

pytestmark = pytest.mark.integration

ARN = "arn:aws:iam::123456789012:role/keystone-deploy-prod"
DIGEST = "sha256:" + "cd" * 32
TEMPLATE: dict[str, JsonValue] = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
}


class FakeConnector:
    def __init__(self, outcome: Exception | None = None) -> None:
        self.outcome = outcome
        self.requests: list[MintRequest] = []

    def mint(self, request: MintRequest) -> IssuedCredential:
        self.requests.append(request)
        if self.outcome is not None:
            raise self.outcome
        return IssuedCredential(
            access_key_id="ASIAFAKE0123456789AB",
            secret_access_key="never-stored",
            session_token="never-stored-either",
            expiration=datetime.now(UTC) + timedelta(seconds=request.duration_seconds),
        )

    def describe_capabilities(self) -> ConnectorCapabilities:
        return ConnectorCapabilities("fake", 3600, True, True, True)

    def validate_registration(self, role_arn: str, external_id: str | None) -> None:
        return None


@pytest.fixture
def fixture_ids(admin_engine: Engine, app_engine: Engine) -> tuple[uuid.UUID, uuid.UUID]:
    with app_engine.begin() as conn:
        registry = RoleRegistry(conn)
        role = registry.register_role(name="deploy-prod", role_arn=ARN, max_ttl_seconds=1800)
        registry.add_template(role_id=role.id, ref="s3-deploy-narrow", policy_document=TEMPLATE)
        registry.register_role(
            name="retired",
            role_arn=ARN.replace("prod", "retired"),
            max_ttl_seconds=900,
            enabled=False,
        )
        pin_id = uuid7()
        conn.execute(
            text(
                "INSERT INTO policy_pins (id, bundle_digest, bundle_sequence, active) "
                "VALUES (:id, :digest, 7, true)"
            ),
            {"id": pin_id, "digest": DIGEST},
        )
    return role.id, pin_id


def _decision(pin_id: uuid.UUID, **overrides: object) -> AuthorizedDecision:
    base: dict[str, object] = {
        "decision_id": uuid7(),
        "decision_audit_seq": 1,
        "grant": "deploy-prod",
        "ttl_cap_seconds": 1800,
        "session_policy_ref": "s3-deploy-narrow",
        "rule_path": "keystone.grants.deploy_prod",
        "policy_digest": DIGEST,
        "policy_pin_id": pin_id,
    }
    base.update(overrides)
    return AuthorizedDecision(**base)  # type: ignore[arg-type]


def _identity(jti: bytes = b"\x07" * 32) -> IdentityContext:
    return IdentityContext(
        jti_hash=jti,
        actor="octocat",
        repository="acme/app",
        repository_id="42",
        run_id="1234",
        ref="refs/heads/main",
        workflow_ref="acme/app/.github/workflows/deploy.yml@refs/heads/main",
        claims={"repository": "acme/app", "ref": "refs/heads/main"},
    )


def _events(engine: Engine) -> list[tuple[str, dict[str, JsonValue]]]:
    with engine.connect() as conn:
        head = snapshot_head(conn)
        events = load_events(conn, 1, head.seq)
        assert verify_chain(events, expected_head=head).ok
    out: list[tuple[str, dict[str, JsonValue]]] = []
    for e in events:
        assert isinstance(e.details, dict)
        data = e.details["data"]
        assert isinstance(data, dict)
        out.append((e.event_type, data))
    return out


def test_golden_path_orders_audit_and_state_correctly(
    app_engine: Engine, fixture_ids: tuple[uuid.UUID, uuid.UUID]
) -> None:
    _, pin_id = fixture_ids
    connector = FakeConnector()
    service = IssuanceService(app_engine, PostgresAuditSink(), connector)

    result = service.issue(_decision(pin_id), _identity(), requested_ttl_seconds=3600)

    assert result.granted_ttl_seconds == 1800 and result.ttl_clamped and not result.ttl_raised
    assert result.issuance.state is IssuanceState.ISSUED
    assert result.issuance.access_key_prefix == "ASIAFAKE"
    assert result.credential.secret_access_key == "never-stored"

    request = connector.requests[0]
    assert request.session_name == "ks-42-1234-1"
    assert request.duration_seconds == 1800
    assert request.session_policy == TEMPLATE
    assert request.tags["keystone:repository"] == "acme/app"

    with app_engine.connect() as conn:
        stored = IssuanceRepository(conn).get(result.issuance.id)
        assert stored is not None and stored.state is IssuanceState.ISSUED
        assert stored.access_key_prefix == "ASIAFAKE" and stored.expires_at is not None
        columns = conn.execute(text("SELECT * FROM issuances")).one()._mapping
    assert "never-stored" not in str(dict(columns))

    events = _events(app_engine)
    assert [t for t, _ in events] == [EventType.CREDENTIAL_ISSUED.value]
    data = events[0][1]
    assert data["access_key_prefix"] == "ASIAFAKE" and data["ttl_clamped"] is True
    assert "never-stored" not in str(data)

    service.mark_delivered(result.issuance.id)
    with app_engine.connect() as conn:
        assert IssuanceRepository(conn).get(result.issuance.id).state is IssuanceState.DELIVERED  # type: ignore[union-attr]
    with pytest.raises(IllegalTransition):
        service.mark_delivered(result.issuance.id)


def test_indeterminate_is_recorded_not_retried(
    app_engine: Engine, fixture_ids: tuple[uuid.UUID, uuid.UUID]
) -> None:
    _, pin_id = fixture_ids
    connector = FakeConnector(IndeterminateError("lost"))
    service = IssuanceService(app_engine, PostgresAuditSink(), connector)
    with pytest.raises(IndeterminateError):
        service.issue(_decision(pin_id), _identity(), None)
    assert len(connector.requests) == 1
    with app_engine.connect() as conn:
        pending = IssuanceRepository(conn).non_terminal()
    assert [p.state for p in pending] == [IssuanceState.INDETERMINATE]
    assert [t for t, _ in _events(app_engine)] == [EventType.STS_INDETERMINATE.value]


def test_access_denied_marks_failed_and_audits(
    app_engine: Engine, fixture_ids: tuple[uuid.UUID, uuid.UUID]
) -> None:
    _, pin_id = fixture_ids
    service = IssuanceService(
        app_engine, PostgresAuditSink(), FakeConnector(AccessDeniedError("drift"))
    )
    with pytest.raises(AccessDeniedError):
        service.issue(_decision(pin_id), _identity(), None)
    with app_engine.connect() as conn:
        assert IssuanceRepository(conn).non_terminal() == []
    events = _events(app_engine)
    assert events[0][0] == EventType.CREDENTIAL_ISSUE_FAILED.value
    assert events[0][1]["error_class"] == "AccessDeniedError" and events[0][1]["http_status"] == 502


def test_disabled_role_never_reaches_the_connector(
    app_engine: Engine, fixture_ids: tuple[uuid.UUID, uuid.UUID]
) -> None:
    _, pin_id = fixture_ids
    connector = FakeConnector()
    service = IssuanceService(app_engine, PostgresAuditSink(), connector)
    with pytest.raises(RegistryError) as info:
        service.issue(_decision(pin_id, grant="retired"), _identity(), None)
    assert info.value.code.value == "REGISTRY_ROLE_DISABLED"
    with pytest.raises(RegistryError):
        service.issue(_decision(pin_id, grant="never-registered"), _identity(), None)
    assert connector.requests == []
    with app_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM issuances")).scalar_one() == 0
    reasons = [d["reason"] for _, d in _events(app_engine)]
    assert reasons == ["REGISTRY_ROLE_DISABLED", "REGISTRY_ROLE_UNKNOWN"]


def test_policy_registry_divergence_is_500_and_audited(
    app_engine: Engine, fixture_ids: tuple[uuid.UUID, uuid.UUID]
) -> None:
    _, pin_id = fixture_ids
    connector = FakeConnector()
    service = IssuanceService(app_engine, PostgresAuditSink(), connector)
    with pytest.raises(PolicyRegistryDivergence):
        service.issue(
            _decision(pin_id, ttl_cap_seconds=3600), _identity(), None
        )  # registry max is 1800
    with pytest.raises(RegistryError, match="not approved"):
        service.issue(_decision(pin_id, session_policy_ref="not-approved"), _identity(), None)
    assert connector.requests == []
    assert [d["reason"] for _, d in _events(app_engine)] == [
        "POLICY_REGISTRY_DIVERGENCE",
        "TEMPLATE_UNKNOWN",
    ]


def test_strict_ttl_grant_denies_excess(
    app_engine: Engine, fixture_ids: tuple[uuid.UUID, uuid.UUID]
) -> None:
    _, pin_id = fixture_ids
    service = IssuanceService(app_engine, PostgresAuditSink(), FakeConnector())
    with pytest.raises(TtlDenied):
        service.issue(_decision(pin_id, deny_on_ttl_excess=True), _identity(), 3600)
    assert [d["reason"] for _, d in _events(app_engine)] == ["TTL_EXCEEDS_ALLOWED"]


def test_replayed_jti_cannot_create_a_second_issuance(
    app_engine: Engine, fixture_ids: tuple[uuid.UUID, uuid.UUID]
) -> None:
    _, pin_id = fixture_ids
    service = IssuanceService(app_engine, PostgresAuditSink(), FakeConnector())
    service.issue(_decision(pin_id), _identity(), None)
    with pytest.raises(IntegrityError):
        service.issue(_decision(pin_id, decision_audit_seq=2), _identity(), None)


def test_crash_after_authorize_leaves_a_row_for_the_reconciler(
    app_engine: Engine, fixture_ids: tuple[uuid.UUID, uuid.UUID]
) -> None:
    _, pin_id = fixture_ids

    class Crashing(FakeConnector):
        def mint(self, request: MintRequest) -> IssuedCredential:
            raise RuntimeError("process died mid-call")

    service = IssuanceService(app_engine, PostgresAuditSink(), Crashing())
    with pytest.raises(RuntimeError):
        service.issue(_decision(pin_id), _identity(), None)
    with app_engine.connect() as conn:
        pending = IssuanceRepository(conn).non_terminal()
    assert [p.state for p in pending] == [IssuanceState.AUTHORIZED]
    assert _events(app_engine) == []  # nothing claimed issued


class _SinkThatFailsOnIssued(PostgresAuditSink):
    def append(self, connection: Connection, event: AuditEventInput) -> StoredEvent:
        if event.event_type is EventType.CREDENTIAL_ISSUED:
            raise RuntimeError("database gone after mint")
        return super().append(connection, event)


def test_mint_succeeded_but_audit_failed_returns_nothing_and_leaves_row_for_reconciler(
    app_engine: Engine, fixture_ids: tuple[uuid.UUID, uuid.UUID]
) -> None:
    _, pin_id = fixture_ids
    connector = FakeConnector()
    service = IssuanceService(app_engine, _SinkThatFailsOnIssued(), connector)
    with pytest.raises(RuntimeError, match="database gone"):
        service.issue(_decision(pin_id), _identity(), None)
    assert len(connector.requests) == 1
    with app_engine.connect() as conn:
        pending = IssuanceRepository(conn).non_terminal()
        assert [p.state for p in pending] == [IssuanceState.AUTHORIZED]
        assert pending[0].access_key_prefix is None
    assert _events(app_engine) == []


def test_identity_claims_cannot_smuggle_a_token() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="forbidden key"):
        IdentityContext(
            jti_hash=bytes(32),
            actor="a",
            repository="r",
            repository_id="1",
            run_id="1",
            ref="x",
            workflow_ref="w",
            claims={"id_token": "eyJ..."},
        )
