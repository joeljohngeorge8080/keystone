"""Ch. 61 per-stage latency budgets against real dependencies: verify <= 15 ms, OPA <= 20 ms,
audit commit <= 25 ms (p95). STS is external and has no budget here.

Opt-in (`KEYSTONE_RUN_PERF=1`): timings on a shared CI runner are noise, so the default suite
never fails on them. Each stage is warmed up, then timed over SAMPLES iterations; the p50/p95
are printed (`-s`) and the p95 is asserted against the budget.
"""

from __future__ import annotations

import os
import shutil
import statistics
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
import redis
from sqlalchemy.engine import Engine

from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import PostgresAuditSink
from keystone.audit.store import load_events, snapshot_head
from keystone.audit.verify import verify_chain
from keystone.authz.evaluator import OpaHttpEvaluator
from keystone.authz.service import build_policy_input
from keystone.db.ids import uuid7
from keystone.identity.jwks import JwksCache
from keystone.identity.oidc import GitHubOidcVerifier
from keystone.identity.replay import RedisReplayStore
from tests.integration.test_authorization_opa import REVISION, _identity, opa_server  # noqa: F401
from tests.integration.test_oidc_forgery_suite import (
    AUDIENCE,
    ISSUER,
    FakeOrigin,
    KeyPair,
    good_claims,
    sign,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.perf,
    pytest.mark.skipif(
        os.environ.get("KEYSTONE_RUN_PERF") != "1", reason="set KEYSTONE_RUN_PERF=1"
    ),
]

SAMPLES = 300
WARMUP = 30
VERIFY_BUDGET_MS = 15.0
OPA_BUDGET_MS = 20.0
AUDIT_COMMIT_BUDGET_MS = 25.0


def _measure(name: str, operation: Callable[[int], object], budget_ms: float) -> None:
    for i in range(WARMUP):
        operation(-1 - i)
    samples = []
    for i in range(SAMPLES):
        started = time.perf_counter()
        operation(i)
        samples.append((time.perf_counter() - started) * 1000)
    samples.sort()
    p50 = statistics.median(samples)
    p95 = samples[int(len(samples) * 0.95) - 1]
    print(f"\n{name}: p50 {p50:.2f} ms, p95 {p95:.2f} ms (budget {budget_ms:.0f} ms)")
    assert p95 <= budget_ms, f"{name} p95 {p95:.2f} ms exceeds the {budget_ms} ms budget"


def test_verify_stage_budget(redis_client: redis.Redis) -> None:
    pair = KeyPair("kid-1")
    verifier = GitHubOidcVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks=JwksCache(redis_client, FakeOrigin(pair), sleep=lambda _: None),
        replay=RedisReplayStore(redis_client),
    )
    # Tokens are signed up front: signing is the issuer's cost, not the broker's. Each one has a
    # fresh JTI, so every timed call includes the replay SET NX round trip.
    tokens = [sign(pair, good_claims(datetime.now(UTC))) for _ in range(WARMUP + SAMPLES)]
    queue = iter(tokens)
    _measure(
        "verify (signature + claims + JWKS cache + replay)",
        lambda _: verifier.verify(next(queue), decision_id=uuid7()),
        VERIFY_BUDGET_MS,
    )


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH")
def test_opa_stage_budget(opa_server: str) -> None:  # noqa: F811
    evaluator = OpaHttpEvaluator(opa_server)
    policy_input = build_policy_input(
        _identity(),
        grant="deploy-prod",
        requested_ttl_seconds=900,
        source_ip="203.0.113.9",
        received_at=datetime.now(UTC),
        keystone_version="0.1.0",
        policy_digest=REVISION,
    )
    _measure(
        "opa evaluation (HTTP sidecar)", lambda _: evaluator.evaluate(policy_input), OPA_BUDGET_MS
    )


def test_audit_commit_budget(app_engine: Engine) -> None:
    sink = PostgresAuditSink()

    def commit(i: int) -> object:
        event = AuditEventInput(
            event_type=EventType.DECISION_ALLOWED,
            occurred_at=datetime.now(UTC),
            actor="repo:acme/app:ref:refs/heads/main",
            data={"decision_id": str(uuid7()), "grant": "deploy-prod", "n": i},
        )
        with app_engine.begin() as conn:
            return sink.append(conn, event)

    _measure("audit commit (chain-head lock + insert + commit)", commit, AUDIT_COMMIT_BUDGET_MS)


def test_chain_head_serialization_ceiling(app_engine: Engine) -> None:
    """Ch. 61: find the append ceiling the single chain-head row imposes, under contention, and
    prove contention never costs integrity: contiguous seqs and a chain that still verifies."""
    sink = PostgresAuditSink()
    writers, per_writer = 16, 40

    def write(writer: int) -> None:
        for i in range(per_writer):
            event = AuditEventInput(
                event_type=EventType.DECISION_ALLOWED,
                occurred_at=datetime.now(UTC),
                actor=f"writer-{writer}",
                data={"decision_id": str(uuid7()), "n": i},
            )
            with app_engine.begin() as conn:
                sink.append(conn, event)

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=writers) as pool:
        list(pool.map(write, range(writers)))
    elapsed = time.perf_counter() - started
    total = writers * per_writer
    print(f"\nchain-head ceiling: {total / elapsed:.0f} appends/s with {writers} writers")
    with app_engine.connect() as conn:
        head = snapshot_head(conn)
        events = load_events(conn, 1, head.seq)
    assert head.seq == total and [e.seq for e in events] == list(range(1, total + 1))
    assert verify_chain(events, expected_head=head).ok
