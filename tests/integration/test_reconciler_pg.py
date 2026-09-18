"""Issuance reconciler (R6): single-transaction append + transition, CloudTrail-lag aware."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.stub import Stubber
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import PostgresAuditSink
from keystone.audit.store import load_events, snapshot_head
from keystone.audit.verify import StoredEvent, verify_chain
from keystone.broker.issuance import IssuanceRepository, IssuanceState
from keystone.broker.reconcile import (
    CloudTrailSessionLookup,
    IssuanceReconciler,
    LookupUnavailable,
    Outcome,
    SessionRecord,
)
from keystone.db.ids import uuid7
from keystone.registry.repo import RoleRegistry

pytestmark = pytest.mark.integration

ARN = "arn:aws:iam::123456789012:role/keystone-deploy-prod"


class FakeLookup:
    def __init__(self) -> None:
        self.sessions: dict[str, SessionRecord] = {}
        self.fail = False
        self.calls: list[str] = []

    def find_session(self, session_name: str, *, not_before: datetime) -> SessionRecord | None:
        self.calls.append(session_name)
        if self.fail:
            raise LookupUnavailable("cloudtrail down")
        return self.sessions.get(session_name)


class Clock:
    def __init__(self) -> None:
        self.now = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def seeded(app_engine: Engine) -> tuple[uuid.UUID, uuid.UUID]:
    with app_engine.begin() as conn:
        role = RoleRegistry(conn).register_role(
            name="deploy-prod", role_arn=ARN, max_ttl_seconds=3600
        )
        pin_id = uuid7()
        conn.execute(
            text(
                "INSERT INTO policy_pins (id, bundle_digest, bundle_sequence, active) "
                "VALUES (:id, :d, 1, true)"
            ),
            {"id": pin_id, "d": "sha256:" + "ab" * 32},
        )
    return role.id, pin_id


def _row(
    engine: Engine,
    seeded: tuple[uuid.UUID, uuid.UUID],
    state: IssuanceState,
    n: int,
    *,
    age: timedelta,
) -> uuid.UUID:
    role_id, pin_id = seeded
    with engine.begin() as conn:
        issuance = IssuanceRepository(conn).create_authorized(
            jti_hash=n.to_bytes(32, "big"),
            target_role_id=role_id,
            policy_pin_id=pin_id,
            grant_name="deploy-prod",
            session_name=f"ks-42-{n}-{n}",
            session_policy_ref="s3",
            granted_ttl_seconds=900,
            identity_claims={"repository": "acme/app"},
        )
        conn.execute(
            text("UPDATE issuances SET created_at = now() - :age WHERE id = :id"),
            {"age": age, "id": issuance.id},
        )
        if state is IssuanceState.ISSUED:
            IssuanceRepository(conn).transition(
                issuance.id,
                IssuanceState.AUTHORIZED,
                IssuanceState.ISSUED,
                access_key_prefix="ASIAXXXX",
            )
        elif state is IssuanceState.INDETERMINATE:
            IssuanceRepository(conn).transition(
                issuance.id, IssuanceState.AUTHORIZED, IssuanceState.INDETERMINATE
            )
    return issuance.id


def _state(engine: Engine, issuance_id: uuid.UUID) -> IssuanceState:
    with engine.connect() as conn:
        row = IssuanceRepository(conn).get(issuance_id)
        assert row is not None
        return row.state


def _events(engine: Engine) -> list[StoredEvent]:
    with engine.connect() as conn:
        head = snapshot_head(conn)
        events = load_events(conn, 1, head.seq)
        assert verify_chain(events, expected_head=head).ok
    return events


def test_crash_before_outcome_becomes_indeterminate_then_resolves(
    app_engine: Engine, seeded: tuple[uuid.UUID, uuid.UUID]
) -> None:
    lookup = FakeLookup()
    reconciler = IssuanceReconciler(app_engine, PostgresAuditSink(), lookup, clock=Clock())
    row = _row(app_engine, seeded, IssuanceState.AUTHORIZED, 1, age=timedelta(minutes=2))

    report = reconciler.run_once()
    assert report.outcomes == {Outcome.MARKED_INDETERMINATE: 1}
    assert _state(app_engine, row) is IssuanceState.INDETERMINATE
    assert [e.event_type for e in _events(app_engine)] == [EventType.STS_INDETERMINATE.value]

    # Still inside the consistency window, still no session: nothing changes, no new rows.
    assert reconciler.run_once().outcomes == {Outcome.LEFT_INDETERMINATE: 1}
    assert len(_events(app_engine)) == 1

    # CloudTrail catches up: a session exists that nobody received.
    lookup.sessions["ks-42-1-1"] = SessionRecord("ks-42-1-1", "ASIAFOUN", datetime.now(UTC))
    assert reconciler.run_once().outcomes == {Outcome.RECONCILED_ISSUED: 1}
    assert _state(app_engine, row) is IssuanceState.DELIVERED
    events = _events(app_engine)
    assert events[-1].event_type == EventType.ISSUED_UNDELIVERED.value
    assert events[-1].details["data"]["access_key_prefix"] == "ASIAFOUN"  # type: ignore[index,call-overload]
    with app_engine.connect() as conn:
        stored = IssuanceRepository(conn).get(row)
        assert (
            stored is not None
            and stored.access_key_prefix == "ASIAFOUN"
            and stored.expires_at is not None
        )

    assert reconciler.run_once().scanned == 0  # terminal rows are never rescanned


def test_no_session_beyond_the_window_is_failed_not_before(
    app_engine: Engine, seeded: tuple[uuid.UUID, uuid.UUID]
) -> None:
    lookup = FakeLookup()
    reconciler = IssuanceReconciler(app_engine, PostgresAuditSink(), lookup, clock=Clock())
    young = _row(app_engine, seeded, IssuanceState.INDETERMINATE, 2, age=timedelta(minutes=19))
    old = _row(app_engine, seeded, IssuanceState.INDETERMINATE, 3, age=timedelta(minutes=21))
    report = reconciler.run_once()
    assert report.outcomes == {Outcome.LEFT_INDETERMINATE: 1, Outcome.RECONCILED_FAILED: 1}
    assert _state(app_engine, young) is IssuanceState.INDETERMINATE
    assert _state(app_engine, old) is IssuanceState.FAILED
    events = _events(app_engine)
    assert [e.event_type for e in events] == [EventType.CREDENTIAL_ISSUE_FAILED.value]
    assert events[0].details["data"]["reason"] == "reconciled_no_session_after_window"  # type: ignore[index,call-overload]


def test_issued_but_never_marked_delivered_is_closed_after_grace(
    app_engine: Engine, seeded: tuple[uuid.UUID, uuid.UUID]
) -> None:
    reconciler = IssuanceReconciler(app_engine, PostgresAuditSink(), FakeLookup(), clock=Clock())
    fresh = _row(app_engine, seeded, IssuanceState.ISSUED, 4, age=timedelta(minutes=1))
    stale = _row(app_engine, seeded, IssuanceState.ISSUED, 5, age=timedelta(minutes=6))
    assert reconciler.run_once().outcomes == {
        Outcome.LEFT_INDETERMINATE: 1,
        Outcome.UNDELIVERED_CLOSED: 1,
    }
    assert _state(app_engine, fresh) is IssuanceState.ISSUED
    assert _state(app_engine, stale) is IssuanceState.DELIVERED
    assert _events(app_engine)[0].details["data"]["reason"] == "delivery_unconfirmed"  # type: ignore[index,call-overload]


def test_lookup_outage_skips_rows_and_never_fails_them(
    app_engine: Engine, seeded: tuple[uuid.UUID, uuid.UUID]
) -> None:
    lookup = FakeLookup()
    lookup.fail = True
    reconciler = IssuanceReconciler(app_engine, PostgresAuditSink(), lookup, clock=Clock())
    row = _row(app_engine, seeded, IssuanceState.INDETERMINATE, 6, age=timedelta(hours=2))
    assert reconciler.run_once().outcomes == {Outcome.SKIPPED_LOOKUP_ERROR: 1}
    assert _state(app_engine, row) is IssuanceState.INDETERMINATE
    assert _events(app_engine) == []


def test_append_and_transition_are_one_transaction(
    app_engine: Engine, seeded: tuple[uuid.UUID, uuid.UUID]
) -> None:
    class DyingSink(PostgresAuditSink):
        def append(self, connection: Connection, event: AuditEventInput) -> StoredEvent:
            raise RuntimeError("db lost mid-reconcile")

    lookup = FakeLookup()
    lookup.sessions["ks-42-7-7"] = SessionRecord("ks-42-7-7", "ASIAAAAA", datetime.now(UTC))
    reconciler = IssuanceReconciler(app_engine, DyingSink(), lookup, clock=Clock())
    row = _row(app_engine, seeded, IssuanceState.AUTHORIZED, 7, age=timedelta(minutes=1))
    with pytest.raises(RuntimeError):
        reconciler.run_once()
    assert (
        _state(app_engine, row) is IssuanceState.AUTHORIZED
    )  # transition rolled back with the audit
    assert _events(app_engine) == []
    # A later run with a healthy sink completes exactly once.
    healthy = IssuanceReconciler(app_engine, PostgresAuditSink(), lookup, clock=Clock())
    assert healthy.run_once().outcomes == {Outcome.RECONCILED_ISSUED: 1}
    assert healthy.run_once().scanned == 0


def test_cloudtrail_lookup_joins_on_role_session_name() -> None:
    client = boto3.client(
        "cloudtrail", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y"
    )
    stubber = Stubber(client)
    minted = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)

    def event(name: str, key: str) -> dict[str, object]:
        return {
            "EventName": "AssumeRole",
            "EventTime": minted,
            "CloudTrailEvent": json.dumps(
                {
                    "eventTime": "2026-09-19T12:00:00Z",
                    "requestParameters": {"roleSessionName": name},
                    "responseElements": {"credentials": {"accessKeyId": key}},
                }
            ),
        }

    stubber.add_response(
        "lookup_events",
        {
            "Events": [
                event("ks-1-1-1", "ASIAONE0000000000000"),
                event("ks-2-2-2", "ASIATWO0000000000000"),
            ]
        },
    )
    stubber.activate()
    lookup = CloudTrailSessionLookup(client)
    found = lookup.find_session("ks-2-2-2", not_before=minted - timedelta(minutes=5))
    assert found == SessionRecord("ks-2-2-2", "ASIATWO0", minted)
    stubber.assert_no_pending_responses()

    stubber.add_response("lookup_events", {"Events": []})
    assert lookup.find_session("ks-9-9-9", not_before=minted) is None

    stubber.add_client_error("lookup_events", service_error_code="Throttling", http_status_code=429)
    with pytest.raises(LookupUnavailable):
        lookup.find_session("ks-1-1-1", not_before=minted)
