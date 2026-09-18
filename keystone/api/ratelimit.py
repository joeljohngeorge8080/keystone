"""Three-tier rate limiting (Ch. 29 as corrected by R3): token buckets in one atomic Lua script.

Tier 0  global shedding rate before signature verification (protects verify CPU; not IP-keyed,
        not a hard concurrency ceiling).
Tier 1  per verified identity (`sub`) and per repository (`repository_id`) — the authoritative
        per-tenant control, after verification, before OPA.
Tier 2  global in-flight STS-call cap (STS-quota self-guard).
Redis unavailable => DependencyUnavailable (503), never "allow".
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import redis

from keystone.db.redis import guarded

# KEYS[1] bucket hash; ARGV: capacity, refill_per_ms, now_ms, cost, idle_expiry_ms
_TOKEN_BUCKET = """
local bucket = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_ms = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local expiry_ms = tonumber(ARGV[5])
local state = redis.call('HMGET', bucket, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil then tokens = capacity; ts = now_ms end
if now_ms > ts then tokens = math.min(capacity, tokens + (now_ms - ts) * refill_per_ms) end
local allowed = 0
local retry_after_ms = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  retry_after_ms = math.ceil((cost - tokens) / refill_per_ms)
end
redis.call('HSET', bucket, 'tokens', tokens, 'ts', now_ms)
redis.call('PEXPIRE', bucket, expiry_ms)
return {allowed, math.floor(tokens), retry_after_ms}
"""  # noqa: S105 — Lua source, not a secret

# KEYS[1] counter; ARGV: cap, ttl_ms  -> {acquired, current}
_INFLIGHT_ACQUIRE = """
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
if current >= tonumber(ARGV[1]) then return {0, current} end
current = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]))
return {1, current}
"""


class RateLimited(Exception):
    http_status = 429

    def __init__(self, code: str, scope: str, retry_after_seconds: int) -> None:
        super().__init__(f"{code} ({scope}); retry after {retry_after_seconds}s")
        self.code = code
        self.scope = scope
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True, slots=True)
class BucketPolicy:
    """`limit` events per `window_seconds`, with `burst` tokens available instantly."""

    limit: int
    window_seconds: int
    burst: int

    @property
    def refill_per_ms(self) -> float:
        return self.limit / (self.window_seconds * 1000.0)

    def with_limit(self, limit: int) -> BucketPolicy:
        return BucketPolicy(limit=limit, window_seconds=self.window_seconds, burst=self.burst)


@dataclass(frozen=True, slots=True)
class Verdict:
    allowed: bool
    remaining: int
    retry_after_seconds: int


DEFAULT_TIER0 = BucketPolicy(
    limit=1000, window_seconds=1, burst=2000
)  # 5x the 200 rps burst target
DEFAULT_IDENTITY = BucketPolicy(limit=30, window_seconds=300, burst=10)
DEFAULT_REPOSITORY = BucketPolicy(limit=60, window_seconds=300, burst=20)
DEFAULT_STS_INFLIGHT_CAP = 20
_IDLE_EXPIRY_FACTOR = 2


class TokenBuckets:
    def __init__(self, client: redis.Redis, clock_ms: Callable[[], int]) -> None:
        self._redis = client
        self._clock_ms = clock_ms
        self._script = client.register_script(_TOKEN_BUCKET)

    def take(self, key: str, policy: BucketPolicy, cost: int = 1) -> Verdict:
        idle_expiry_ms = policy.window_seconds * 1000 * _IDLE_EXPIRY_FACTOR
        raw = guarded(
            lambda: self._script(
                keys=[key],
                args=[policy.burst, policy.refill_per_ms, self._clock_ms(), cost, idle_expiry_ms],
            )
        )
        allowed, remaining, retry_after_ms = (int(v) for v in raw)
        return Verdict(
            allowed=allowed == 1,
            remaining=remaining,
            retry_after_seconds=max(1, math.ceil(retry_after_ms / 1000)) if not allowed else 0,
        )


class Tier0Shedder:
    """Global pre-verification shedding rate (R3). One bucket for the whole broker."""

    KEY = "rl:t0:global"

    def __init__(self, buckets: TokenBuckets, policy: BucketPolicy = DEFAULT_TIER0) -> None:
        self._buckets = buckets
        self._policy = policy

    def check(self) -> None:
        verdict = self._buckets.take(self.KEY, self._policy)
        if not verdict.allowed:
            raise RateLimited("KEYSTONE_OVERLOADED", "tier0", verdict.retry_after_seconds)


OverrideLookup = Callable[[str, str], int | None]  # (scope, subject) -> per_minute override


class Tier1Limiter:
    """Per verified identity and per repository (R3): the authoritative per-tenant control."""

    def __init__(
        self,
        buckets: TokenBuckets,
        *,
        identity_policy: BucketPolicy = DEFAULT_IDENTITY,
        repository_policy: BucketPolicy = DEFAULT_REPOSITORY,
        overrides: OverrideLookup | None = None,
    ) -> None:
        self._buckets = buckets
        self._identity_policy = identity_policy
        self._repository_policy = repository_policy
        self._overrides = overrides or (lambda scope, subject: None)

    @staticmethod
    def _identity_key(sub: str) -> str:
        # Subjects are long and attacker-influenced; hash them so keys are fixed-size.
        return "rl:id:" + hashlib.sha256(sub.encode("utf-8")).hexdigest()

    def _policy_for(self, scope: str, subject: str, default: BucketPolicy) -> BucketPolicy:
        override = self._overrides(scope, subject)
        if override is None:
            return default
        return default.with_limit(max(0, override) * (default.window_seconds // 60))

    def check(self, *, sub: str, repository_id: str) -> None:
        identity_policy = self._policy_for("identity", sub, self._identity_policy)
        repo_policy = self._policy_for("repository", repository_id, self._repository_policy)
        verdict = self._buckets.take(self._identity_key(sub), identity_policy)
        if not verdict.allowed:
            raise RateLimited("RATE_LIMITED_IDENTITY", "identity", verdict.retry_after_seconds)
        verdict = self._buckets.take(f"rl:repo:{repository_id}", repo_policy)
        if not verdict.allowed:
            raise RateLimited("RATE_LIMITED_REPOSITORY", "repository", verdict.retry_after_seconds)


class StsInflightGuard:
    """Tier 2: bounded concurrent STS calls. Slots self-expire so a crash cannot leak them."""

    KEY = "rl:sts:inflight"

    def __init__(
        self, client: redis.Redis, cap: int = DEFAULT_STS_INFLIGHT_CAP, slot_ttl_ms: int = 30_000
    ) -> None:
        self._redis = client
        self._cap = cap
        self._slot_ttl_ms = slot_ttl_ms
        self._acquire = client.register_script(_INFLIGHT_ACQUIRE)

    @contextmanager
    def slot(self) -> Iterator[None]:
        acquired, _ = guarded(
            lambda: self._acquire(keys=[self.KEY], args=[self._cap, self._slot_ttl_ms])
        )
        if int(acquired) != 1:
            raise RateLimited("STS_CAPACITY_EXHAUSTED", "sts-inflight", 1)
        try:
            yield
        finally:
            guarded(lambda: self._redis.decr(self.KEY))
