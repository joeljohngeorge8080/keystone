"""Replay store, three-tier rate limiting, bounded aggregation — against real Redis (+ PostgreSQL)."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
import redis
from sqlalchemy.engine import Engine

from keystone.api.ratelimit import (
    BucketPolicy,
    RateLimited,
    StsInflightGuard,
    Tier0Shedder,
    Tier1Limiter,
    TokenBuckets,
)
from keystone.audit.aggregation import OVERFLOW_KEY, AggregatedFailure, FailureAggregator
from keystone.audit.events import EventType
from keystone.audit.sink import PostgresAuditSink
from keystone.audit.store import load_events, snapshot_head
from keystone.audit.verify import verify_chain
from keystone.db.ids import uuid7
from keystone.db.redis import DependencyUnavailable, make_redis
from keystone.identity.replay import RedisReplayStore, jti_hash, replay_ttl_ms

pytestmark = pytest.mark.integration


class FakeClock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def ms(self) -> int:
        return int(self.now.timestamp() * 1000)

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _keys(client: redis.Redis) -> list[bytes]:
    return cast(list[bytes], client.keys())


def _hgetall(client: redis.Redis, key: bytes) -> dict[bytes, bytes]:
    return cast(dict[bytes, bytes], client.hgetall(key.decode()))


def _int(value: Any) -> int:
    return int(value or 0)


# ---------------------------------------------------------------- replay


def test_jti_is_consumed_exactly_once(redis_client: redis.Redis) -> None:
    store = RedisReplayStore(redis_client)
    digest = jti_hash("token-jti-1")
    assert store.consume(digest, uuid7(), 5_000) is True
    assert store.consume(digest, uuid7(), 5_000) is False  # replay
    assert store.consume(jti_hash("token-jti-2"), uuid7(), 5_000) is True
    assert redis_client.get(b"jti:" + digest.hex().encode()) is not None
    assert b"token-jti-1" not in b"".join(_keys(redis_client))  # raw JTI never stored


def test_concurrent_consumers_only_one_wins(redis_client: redis.Redis) -> None:
    store = RedisReplayStore(redis_client)
    digest = jti_hash("racy")
    wins: list[bool] = []
    lock = threading.Lock()

    def attempt() -> None:
        result = store.consume(digest, uuid7(), 10_000)
        with lock:
            wins.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert wins.count(True) == 1 and wins.count(False) == 15


def test_replay_ttl_outlives_the_token_by_the_skew_window() -> None:
    now = datetime(2026, 9, 19, tzinfo=UTC)
    assert replay_ttl_ms(now + timedelta(seconds=300), now) == 360_000
    assert replay_ttl_ms(now - timedelta(seconds=999), now) == 1_000  # never zero/negative


def test_replay_store_rejects_wrong_digest_length(redis_client: redis.Redis) -> None:
    with pytest.raises(ValueError):
        RedisReplayStore(redis_client).consume(b"short", uuid7(), 1000)


# ---------------------------------------------------------------- rate limiting


def test_token_bucket_burst_then_refill(redis_client: redis.Redis) -> None:
    clock = FakeClock(datetime(2026, 9, 19, tzinfo=UTC))
    buckets = TokenBuckets(redis_client, clock.ms)
    policy = BucketPolicy(limit=30, window_seconds=300, burst=10)
    verdicts = [buckets.take("rl:test", policy) for _ in range(11)]
    assert [v.allowed for v in verdicts] == [True] * 10 + [False]
    assert verdicts[-1].retry_after_seconds == 10  # one token every 10 s at 30 / 300 s
    clock.advance(10)
    assert buckets.take("rl:test", policy).allowed is True
    assert buckets.take("rl:test", policy).allowed is False
    clock.advance(1000)
    assert buckets.take("rl:test", policy).remaining == 9  # capped at burst, not accumulated


def test_tier0_sheds_with_overloaded_code(redis_client: redis.Redis) -> None:
    clock = FakeClock(datetime(2026, 9, 19, tzinfo=UTC))
    shedder = Tier0Shedder(
        TokenBuckets(redis_client, clock.ms), BucketPolicy(limit=1000, window_seconds=1, burst=3)
    )
    shedder.check()
    shedder.check()
    shedder.check()
    with pytest.raises(RateLimited) as info:
        shedder.check()
    assert info.value.code == "KEYSTONE_OVERLOADED" and info.value.retry_after_seconds >= 1


def test_tier1_keys_on_verified_identity_and_repository(redis_client: redis.Redis) -> None:
    clock = FakeClock(datetime(2026, 9, 19, tzinfo=UTC))
    limiter = Tier1Limiter(
        TokenBuckets(redis_client, clock.ms),
        identity_policy=BucketPolicy(limit=30, window_seconds=300, burst=2),
        repository_policy=BucketPolicy(limit=60, window_seconds=300, burst=3),
    )
    limiter.check(sub="repo:acme/app:ref:main", repository_id="42")
    limiter.check(sub="repo:acme/app:ref:main", repository_id="42")
    with pytest.raises(RateLimited) as info:
        limiter.check(sub="repo:acme/app:ref:main", repository_id="42")
    assert info.value.code == "RATE_LIMITED_IDENTITY"
    # A different identity in the same repository still has one repo token left, then repo trips.
    limiter.check(sub="repo:acme/app:ref:dev", repository_id="42")
    with pytest.raises(RateLimited) as info:
        limiter.check(sub="repo:acme/app:ref:other", repository_id="42")
    assert info.value.code == "RATE_LIMITED_REPOSITORY"
    assert not any(k.startswith(b"rl:id:repo:") for k in _keys(redis_client))  # subs are hashed


def test_tier1_registry_override_changes_the_rate(redis_client: redis.Redis) -> None:
    clock = FakeClock(datetime(2026, 9, 19, tzinfo=UTC))
    overrides = {("repository", "7"): 600}  # per minute -> 3000 per 5 min window
    limiter = Tier1Limiter(
        TokenBuckets(redis_client, clock.ms),
        repository_policy=BucketPolicy(limit=60, window_seconds=300, burst=1),
        overrides=lambda scope, subject: overrides.get((scope, subject)),
    )
    limiter.check(sub="a", repository_id="7")
    with pytest.raises(RateLimited) as info:
        limiter.check(sub="b", repository_id="7")
    assert info.value.retry_after_seconds == 1  # refills at 10/s instead of one per 5 s
    clock.advance(0.2)
    limiter.check(sub="c", repository_id="7")


def test_sts_inflight_cap_and_slot_release(redis_client: redis.Redis) -> None:
    guard = StsInflightGuard(redis_client, cap=2, slot_ttl_ms=5_000)
    with guard.slot(), guard.slot():
        with pytest.raises(RateLimited) as info:
            with guard.slot():
                pass
        assert info.value.code == "STS_CAPACITY_EXHAUSTED"
    with guard.slot():
        assert _int(redis_client.get(StsInflightGuard.KEY)) == 1
    assert _int(redis_client.get(StsInflightGuard.KEY)) == 0
    assert _int(redis_client.pttl(StsInflightGuard.KEY)) != 0  # key gone or still expiring


def test_redis_down_fails_closed_everywhere() -> None:
    dead = make_redis("redis://127.0.0.1:1/0", timeout_seconds=0.2)
    clock = FakeClock(datetime(2026, 9, 19, tzinfo=UTC))
    with pytest.raises(DependencyUnavailable):
        RedisReplayStore(dead).consume(jti_hash("x"), uuid7(), 1000)
    with pytest.raises(DependencyUnavailable):
        Tier0Shedder(TokenBuckets(dead, clock.ms)).check()
    with pytest.raises(DependencyUnavailable):
        Tier1Limiter(TokenBuckets(dead, clock.ms)).check(sub="s", repository_id="1")
    with pytest.raises(DependencyUnavailable):
        with StsInflightGuard(dead).slot():
            pass
    with pytest.raises(DependencyUnavailable):
        FailureAggregator(dead).record(AggregatedFailure.AUTH_FAILED, "k", "TOKEN_EXPIRED")


# ---------------------------------------------------------------- aggregation


def _chain(engine: Engine) -> list[tuple[str, dict[str, object]]]:
    with engine.connect() as conn:
        head = snapshot_head(conn)
        events = load_events(conn, 1, head.seq)
        assert verify_chain(events, expected_head=head).ok
    return [(e.event_type, e.details["data"]) for e in events]  # type: ignore[index,call-overload,misc]


def test_aggregation_bounds_cardinality_and_flushes_one_row_per_bucket(
    redis_client: redis.Redis, app_engine: Engine
) -> None:
    clock = FakeClock(datetime(2026, 9, 19, 12, 0, 0, tzinfo=UTC))
    aggregator = FailureAggregator(
        redis_client, clock=lambda: clock.now, max_keys=3, interval_seconds=60
    )

    aggregator.record(AggregatedFailure.AUTH_FAILED, "sub-a", "TOKEN_EXPIRED")
    clock.advance(5)
    aggregator.record(AggregatedFailure.AUTH_FAILED, "sub-a", "TOKEN_EXPIRED")
    aggregator.record(AggregatedFailure.AUTH_FAILED, "sub-b", "TOKEN_SIGNATURE_INVALID")
    aggregator.record(AggregatedFailure.AUTH_FAILED, "sub-c", "TOKEN_EXPIRED")
    for i in range(500):  # attacker rotating identities: must not allocate 500 keys
        aggregator.record(AggregatedFailure.AUTH_FAILED, f"rot-{i}", "TOKEN_EXPIRED")
    aggregator.record(AggregatedFailure.RATE_LIMITED, "42", "RATE_LIMITED_REPOSITORY")

    bucket = _hgetall(
        redis_client, b"agg:auth_failed:" + str(int(clock.now.timestamp()) // 60).encode()
    )
    counted = [k for k in bucket if k.startswith(b"c:")]
    assert len(counted) == 4  # 3 real keys + one overflow bucket, regardless of volume
    assert bucket[b"c:__overflow__|TOKEN_EXPIRED"] == b"500"

    with app_engine.begin() as conn:
        assert aggregator.flush(conn, PostgresAuditSink()) == []  # interval still open
    clock.advance(60)
    with app_engine.begin() as conn:
        flushed = aggregator.flush(conn, PostgresAuditSink())
    assert sorted(f.failure for f in flushed) == [
        AggregatedFailure.AUTH_FAILED,
        AggregatedFailure.RATE_LIMITED,
    ]

    rows = _chain(app_engine)
    assert len(rows) == 5
    by_key = {(t, d["key"]): d for t, d in rows}
    assert by_key[(EventType.AUTH_FAILED.value, "sub-a")]["count"] == 2
    assert (
        by_key[(EventType.AUTH_FAILED.value, "sub-a")]["first_seen"]
        != by_key[(EventType.AUTH_FAILED.value, "sub-a")]["last_seen"]
    )
    overflow = by_key[(EventType.AUTH_FAILED.value, OVERFLOW_KEY)]
    assert overflow["count"] == 500
    assert 450 <= _int(overflow["distinct_key_estimate"]) <= 550  # HyperLogLog estimate
    assert by_key[(EventType.RATE_LIMITED.value, "42")]["failure_code"] == "RATE_LIMITED_REPOSITORY"

    assert not [k for k in _keys(redis_client) if k.startswith(b"agg")]  # buckets consumed
    with app_engine.begin() as conn:
        assert aggregator.flush(conn, PostgresAuditSink()) == []  # idempotent


def test_flush_is_at_least_once_after_a_crash_mid_flush(
    redis_client: redis.Redis, app_engine: Engine
) -> None:
    clock = FakeClock(datetime(2026, 9, 19, 12, 0, 0, tzinfo=UTC))
    aggregator = FailureAggregator(redis_client, clock=lambda: clock.now, interval_seconds=60)
    aggregator.record(AggregatedFailure.TOKEN_REPLAYED, "sub-z", "TOKEN_REPLAYED")
    clock.advance(60)

    class Dying(PostgresAuditSink):
        def append(self, connection, event):  # type: ignore[no-untyped-def]
            raise RuntimeError("worker died")

    with pytest.raises(RuntimeError), app_engine.begin() as conn:
        aggregator.flush(conn, Dying())
    assert [k for k in _keys(redis_client) if k.startswith(b"aggp:")]  # parked, not lost
    with app_engine.begin() as conn:
        flushed = aggregator.flush(conn, PostgresAuditSink())
    assert [f.rows_written for f in flushed] == [1]
    assert _chain(app_engine)[0][1]["key"] == "sub-z"


def test_aggregation_key_charset_is_enforced(redis_client: redis.Redis) -> None:
    with pytest.raises(ValueError):
        FailureAggregator(redis_client).record(AggregatedFailure.AUTH_FAILED, "a|b", "X")
    assert uuid.UUID(str(uuid7())).version == 7
