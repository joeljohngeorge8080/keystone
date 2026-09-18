"""Bounded pre-decision failure aggregation (Ch. 32 as corrected by R4).

High-volume failures are counted per (event_type, interval) in Redis and flushed as ONE chained
audit row per bucket. Cardinality is capped at N keys per bucket; overflow collapses into a single
`__overflow__` bucket with a HyperLogLog distinct-key estimate. The aggregation client MUST point
at a Redis with its own memory budget (separate instance, `allkeys-lru`) so it can never evict
replay-JTI or rate-limit state, which live on the `noeviction` primary.
"""

from __future__ import annotations

import enum
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

import redis
from pydantic import JsonValue
from sqlalchemy.engine import Connection

from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import AuditSink
from keystone.db.redis import guarded

OVERFLOW_KEY = "__overflow__"
DEFAULT_MAX_KEYS = 1024
DEFAULT_INTERVAL_SECONDS = 60
_RETENTION_INTERVALS = 10  # unflushed buckets self-expire rather than accumulate

# KEYS[1] bucket hash, KEYS[2] overflow HLL; ARGV: field, max_keys, now_ms, ttl_ms, raw_key
_RECORD = """
local bucket, hll = KEYS[1], KEYS[2]
local field, raw_key = ARGV[1], ARGV[5]
local max_keys, now_ms, ttl_ms = tonumber(ARGV[2]), ARGV[3], tonumber(ARGV[4])
local existing = redis.call('HGET', bucket, 'c:' .. field)
if existing == false then
  local distinct = tonumber(redis.call('HGET', bucket, 'n') or '0')
  if distinct >= max_keys then
    field = '__overflow__|' .. string.match(field, '|(.*)$')
    redis.call('PFADD', hll, raw_key)
    redis.call('PEXPIRE', hll, ttl_ms)
    if redis.call('HGET', bucket, 'c:' .. field) == false then
      redis.call('HSET', bucket, 'f:' .. field, now_ms)
    end
  else
    redis.call('HINCRBY', bucket, 'n', 1)
    redis.call('HSET', bucket, 'f:' .. field, now_ms)
  end
end
redis.call('HINCRBY', bucket, 'c:' .. field, 1)
redis.call('HSET', bucket, 'l:' .. field, now_ms)
redis.call('PEXPIRE', bucket, ttl_ms)
return 1
"""


class AggregatedFailure(enum.StrEnum):
    AUTH_FAILED = "auth_failed"
    TOKEN_REPLAYED = "token_replayed"  # noqa: S105 — event label
    RATE_LIMITED = "rate_limited"
    PRE_AUTH_SHED = "pre_auth_shed"


_EVENT_TYPE = {
    AggregatedFailure.AUTH_FAILED: EventType.AUTH_FAILED,
    AggregatedFailure.TOKEN_REPLAYED: EventType.TOKEN_REPLAYED,
    AggregatedFailure.RATE_LIMITED: EventType.RATE_LIMITED,
    AggregatedFailure.PRE_AUTH_SHED: EventType.PRE_AUTH_SHED,
}


@dataclass(frozen=True, slots=True)
class FlushedBucket:
    failure: AggregatedFailure
    interval_start: datetime
    rows_written: int


class FailureAggregator:
    def __init__(
        self,
        client: redis.Redis,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        max_keys: int = DEFAULT_MAX_KEYS,
        interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    ) -> None:
        self._redis = client
        self._clock = clock
        self._max_keys = max_keys
        self._interval = interval_seconds
        self._record = client.register_script(_RECORD)

    def _interval_of(self, moment: datetime) -> int:
        return int(moment.timestamp()) // self._interval

    @staticmethod
    def _bucket_key(failure: AggregatedFailure, interval: int) -> str:
        return f"agg:{failure.value}:{interval}"

    def record(self, failure: AggregatedFailure, key: str, failure_code: str) -> None:
        """Count one failure. `key` is the verified identity when known, else a coarse bucket."""
        if "|" in key or "|" in failure_code:
            raise ValueError("aggregation key and code must not contain '|'")
        now = self._clock()
        interval = self._interval_of(now)
        bucket = self._bucket_key(failure, interval)
        ttl_ms = self._interval * 1000 * _RETENTION_INTERVALS
        guarded(
            lambda: self._record(
                keys=[bucket, bucket + ":hll"],
                args=[
                    f"{key}|{failure_code}",
                    self._max_keys,
                    int(now.timestamp() * 1000),
                    ttl_ms,
                    key,
                ],
            )
        )

    def flush(self, connection: Connection, sink: AuditSink) -> list[FlushedBucket]:
        """Write one chained row per closed (event_type, interval) bucket.

        At-least-once: a bucket is renamed to a processing key first, so a crash mid-flush
        re-flushes it rather than losing it.
        """
        current = self._interval_of(self._clock())
        flushed: list[FlushedBucket] = []
        for raw in self._keys("agg:*"):
            name = raw.decode("ascii")
            if name.endswith(":hll"):
                continue
            _, failure_name, interval_text = name.split(":")
            interval = int(interval_text)
            if interval >= current:
                continue  # still open
            processing = f"aggp:{failure_name}:{interval}:{uuid.uuid4().hex}"
            renamed = self._park(name, processing)
            if not renamed:
                continue
            flushed.append(
                self._flush_one(
                    connection, sink, processing, AggregatedFailure(failure_name), interval
                )
            )
        for raw in self._keys("aggp:*"):
            name = raw.decode("ascii")
            if name.endswith(":hll"):
                continue
            _, failure_name, interval_text, _ = name.split(":")
            flushed.append(
                self._flush_one(
                    connection, sink, name, AggregatedFailure(failure_name), int(interval_text)
                )
            )
        return flushed

    def _keys(self, pattern: str) -> list[bytes]:
        return cast(
            list[bytes], guarded(lambda: list(self._redis.scan_iter(match=pattern, count=200)))
        )

    def _park(self, name: str, processing: str) -> bool:
        return bool(guarded(lambda: self._redis.renamenx(name, processing)))

    def _flush_one(
        self,
        connection: Connection,
        sink: AuditSink,
        processing_key: str,
        failure: AggregatedFailure,
        interval: int,
    ) -> FlushedBucket:
        original_hll = f"agg:{failure.value}:{interval}:hll"
        fields = cast(dict[bytes, bytes], guarded(lambda: self._redis.hgetall(processing_key)))
        estimate = (
            int(cast(int, guarded(lambda: self._redis.pfcount(original_hll)))) if fields else 0
        )
        interval_start = datetime.fromtimestamp(interval * self._interval, tz=UTC)
        rows = 0
        for raw_field, raw_count in fields.items():
            field = raw_field.decode("utf-8")
            if not field.startswith("c:"):
                continue
            key, _, code = field[2:].partition("|")
            count = int(raw_count)
            first = int(fields.get(f"f:{key}|{code}".encode(), b"0"))
            last = int(fields.get(f"l:{key}|{code}".encode(), b"0"))
            data: dict[str, JsonValue] = {
                "aggregated": True,
                "interval_start": interval_start.isoformat(),
                "interval_seconds": self._interval,
                "key": key,
                "failure_code": code,
                "count": count,
                "first_seen": datetime.fromtimestamp(first / 1000, tz=UTC).isoformat(),
                "last_seen": datetime.fromtimestamp(last / 1000, tz=UTC).isoformat(),
            }
            if key == OVERFLOW_KEY:
                data["distinct_key_estimate"] = int(estimate)
            sink.append(
                connection,
                AuditEventInput(
                    event_type=_EVENT_TYPE[failure],
                    occurred_at=interval_start,
                    actor=key if key != OVERFLOW_KEY else "aggregate",
                    data=data,
                ),
            )
            rows += 1
        guarded(lambda: self._redis.delete(processing_key, original_hll))
        return FlushedBucket(failure=failure, interval_start=interval_start, rows_written=rows)


def summarize(bucket: FlushedBucket) -> str:
    return json.dumps(
        {
            "failure": bucket.failure.value,
            "interval": bucket.interval_start.isoformat(),
            "rows": bucket.rows_written,
        }
    )
