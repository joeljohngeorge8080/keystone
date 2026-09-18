"""Anchoring + scheduled verification (R7) with PostgreSQL, Redis, and a moto S3 Object Lock bucket."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
import redis
from moto import mock_aws
from sqlalchemy import text
from sqlalchemy.engine import Engine

from keystone.audit.anchor import (
    AnchorBreaker,
    Anchorer,
    AnchorSigner,
    AnchorStoreUnavailable,
    AnchorStoreUnreachable,
    S3ObjectLockAnchorStore,
    last_anchor,
    verify_anchor_signature,
)
from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import PostgresAuditSink
from keystone.audit.store import load_events, snapshot_head
from keystone.audit.verification import ChainDivergence, ChainVerificationTask
from keystone.audit.verify import FindingCode

pytestmark = pytest.mark.integration


class FakeStore:
    def __init__(self) -> None:
        self.objects: dict[int, tuple[bytes, bytes]] = {}
        self.fail = False

    def put(self, chain_seq: int, payload: bytes, signature: bytes) -> str:
        if self.fail:
            raise AnchorStoreUnavailable("s3 unreachable")
        existing = self.objects.get(chain_seq)
        if existing is not None and existing != (payload, signature):
            raise AnchorStoreUnavailable("write-once violation")
        self.objects[chain_seq] = (payload, signature)
        return f"fake://anchors/{chain_seq}"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def _append(engine: Engine, n: int) -> None:
    sink = PostgresAuditSink()
    with engine.begin() as conn:
        for i in range(n):
            sink.append(
                conn,
                AuditEventInput(
                    event_type=EventType.DECISION_ALLOWED,
                    occurred_at=datetime.now(UTC),
                    actor=f"actor-{i}",
                    data={"i": i},
                ),
            )


def _types(engine: Engine) -> list[str]:
    with engine.connect() as conn:
        head = snapshot_head(conn)
        return [e.event_type for e in load_events(conn, 1, head.seq)]


def test_anchor_chain_and_verify(app_engine: Engine, redis_client: redis.Redis) -> None:
    signer = AnchorSigner.generate()
    store = FakeStore()
    clock = Clock()
    breaker = AnchorBreaker(redis_client, threshold=timedelta(minutes=10))
    anchorer = Anchorer(app_engine, PostgresAuditSink(), signer, store, breaker, clock=clock)
    verifier = ChainVerificationTask(app_engine, signer.public_key(), clock=clock)

    assert verifier.run_once().events_verified == 0  # empty chain verifies
    _append(app_engine, 3)
    first = anchorer.anchor_once()
    assert first.anchored and first.chain_seq == 3
    assert set(store.objects) == {3}
    assert _types(app_engine)[-1] == EventType.ANCHOR_WRITTEN.value
    with app_engine.connect() as conn:
        anchor = last_anchor(conn)
    assert anchor is not None and anchor.chain_seq == 3 and anchor.prev_anchor_hash == bytes(32)
    assert verify_anchor_signature(signer.public_key(), anchor)
    payload, signature = store.objects[3]
    assert payload == anchor.canonical and signature == anchor.signature

    # Nothing but our own anchor event since: no churn.
    assert anchorer.anchor_once().reason == "only the previous anchor event is new"
    assert anchorer.anchor_once().anchored is False

    _append(app_engine, 2)
    second = anchorer.anchor_once()
    assert second.anchored and second.chain_seq == 6
    with app_engine.connect() as conn:
        latest = last_anchor(conn)
    assert latest is not None and latest.prev_anchor_hash == anchor.anchor_hash

    result = verifier.run_once()
    assert (result.from_seq, result.to_seq, result.events_verified, result.anchors_verified) == (
        1,
        7,
        7,
        2,
    )
    again = verifier.run_once()
    assert (again.from_seq, again.to_seq, again.events_verified) == (
        8,
        7,
        0,
    )  # nothing new, still consistent
    with app_engine.connect() as conn:
        state = conn.execute(
            text("SELECT last_verified_seq FROM audit_verification_state")
        ).scalar_one()
    assert state == 7
    breaker.check(clock.now + timedelta(hours=5))  # healthy store: a long idle gap never trips it


def test_verification_pages_on_event_and_anchor_tampering(
    app_engine: Engine, admin_engine: Engine, redis_client: redis.Redis
) -> None:
    signer = AnchorSigner.generate()
    clock = Clock()
    anchorer = Anchorer(
        app_engine,
        PostgresAuditSink(),
        signer,
        FakeStore(),
        AnchorBreaker(redis_client),
        clock=clock,
    )
    verifier = ChainVerificationTask(app_engine, signer.public_key(), clock=clock)
    _append(app_engine, 4)
    anchorer.anchor_once()

    with admin_engine.begin() as conn:  # DB operator bypassing the trigger (threat P5)
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_rewrite"))
        conn.execute(
            text(
                "UPDATE audit_events SET canonical_payload = convert_to(replace(convert_from(canonical_payload, 'UTF8'), 'actor-1', 'mallory'), 'UTF8') WHERE seq = 2"
            )
        )
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_rewrite"))
    with pytest.raises(ChainDivergence) as info:
        verifier.run_once()
    assert (info.value.finding.code, info.value.finding.seq) == (FindingCode.HASH_MISMATCH, 2)
    with app_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT last_verified_seq FROM audit_verification_state")
            ).scalar_one()
            == 0
        )

    # Restore the event, then tamper the anchor's signature instead.
    with admin_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_rewrite"))
        conn.execute(
            text(
                "UPDATE audit_events SET canonical_payload = convert_to(replace(convert_from(canonical_payload, 'UTF8'), 'mallory', 'actor-1'), 'UTF8') WHERE seq = 2"
            )
        )
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_rewrite"))
        conn.execute(text("ALTER TABLE audit_anchors DISABLE TRIGGER audit_anchors_no_rewrite"))
        conn.execute(text("UPDATE audit_anchors SET signature = decode(repeat('ab', 64), 'hex')"))
        conn.execute(text("ALTER TABLE audit_anchors ENABLE TRIGGER audit_anchors_no_rewrite"))
    with pytest.raises(ChainDivergence, match="anchor signature invalid"):
        verifier.run_once()


def test_breaker_trips_only_on_store_unreachability(
    app_engine: Engine, redis_client: redis.Redis
) -> None:
    signer = AnchorSigner.generate()
    store = FakeStore()
    clock = Clock()
    breaker = AnchorBreaker(redis_client, threshold=timedelta(minutes=10))
    anchorer = Anchorer(app_engine, PostgresAuditSink(), signer, store, breaker, clock=clock)
    _append(app_engine, 1)

    store.fail = True
    with pytest.raises(AnchorStoreUnavailable):
        anchorer.anchor_once()
    with app_engine.connect() as conn:  # external write failed: no DB row, no anchor event
        assert last_anchor(conn) is None
    assert _types(app_engine) == [EventType.DECISION_ALLOWED.value]

    breaker.check(clock.now + timedelta(minutes=9))  # under threshold: issuance continues
    with pytest.raises(AnchorStoreUnreachable):
        breaker.check(clock.now + timedelta(minutes=11))

    store.fail = False
    clock.now += timedelta(minutes=12)
    assert anchorer.anchor_once().anchored
    breaker.check(clock.now + timedelta(days=1))  # recovered: breaker reset


@mock_aws
def test_s3_object_lock_store_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="keystone-anchors", ObjectLockEnabledForBucket=True)
    store = S3ObjectLockAnchorStore(client, bucket="keystone-anchors", conditional_put=False)
    ref = store.put(42, b'{"chain_seq":42}', b"\x01" * 64)
    assert ref == "s3://keystone-anchors/anchors/chain-0000000000000042.json"
    body = json.loads(
        client.get_object(Bucket="keystone-anchors", Key="anchors/chain-0000000000000042.json")[
            "Body"
        ].read()
    )
    assert body == {"anchor": '{"chain_seq":42}', "signature": "01" * 64}
    head = client.head_object(Bucket="keystone-anchors", Key="anchors/chain-0000000000000042.json")
    assert head.get("ObjectLockMode") == "COMPLIANCE"
