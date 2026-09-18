"""One-time-use JTI (Ch. 30, AMB-2): atomic SET NX, hashed key, TTL that outlives the token."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Protocol

import redis

from keystone.db.redis import guarded

MAX_SKEW_SECONDS = 60


def jti_hash(jti: str) -> bytes:
    return hashlib.sha256(jti.encode("utf-8")).digest()


def replay_ttl_ms(exp: datetime, now: datetime, *, max_skew_seconds: int = MAX_SKEW_SECONDS) -> int:
    """Token can never outlive its replay record: TTL covers exp - now plus the skew window."""
    remaining = (exp - now).total_seconds() + max_skew_seconds
    return max(1000, int(remaining * 1000))


class ReplayStore(Protocol):
    def consume(self, jti_digest: bytes, decision_id: uuid.UUID, ttl_ms: int) -> bool:
        """True if this JTI was unseen and is now consumed; False if it was already used."""
        ...


class RedisReplayStore:
    def __init__(self, client: redis.Redis) -> None:
        self._redis = client

    def consume(self, jti_digest: bytes, decision_id: uuid.UUID, ttl_ms: int) -> bool:
        if len(jti_digest) != 32:
            raise ValueError("jti_digest must be the raw 32-byte SHA-256")
        key = b"jti:" + jti_digest.hex().encode("ascii")
        # SET NX PX is the only allowed primitive (GET-then-SET is a race, AMB-2).
        outcome = guarded(lambda: self._redis.set(key, str(decision_id), nx=True, px=ttl_ms))
        return bool(outcome)
