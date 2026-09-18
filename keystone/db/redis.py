"""Redis access under the fail-closed doctrine (F11): any Redis error is a 503, never a bypass."""

from __future__ import annotations

from collections.abc import Callable

import redis
from redis.exceptions import RedisError


class DependencyUnavailable(Exception):
    """A required dependency is unreachable; the issuance path must answer 503 deny-all (Ch. 27)."""

    http_status = 503
    code = "KEYSTONE_DEPENDENCY_UNAVAILABLE"

    def __init__(self, dependency: str, detail: str = "") -> None:
        super().__init__(f"{dependency} unavailable{': ' + detail if detail else ''}")
        self.dependency = dependency


def make_redis(url: str, *, timeout_seconds: float = 0.25) -> redis.Redis:
    """Short timeouts on purpose: a slow Redis must fail closed fast, not stall issuance."""
    return redis.Redis.from_url(
        url,
        socket_timeout=timeout_seconds,
        socket_connect_timeout=timeout_seconds,
        retry_on_timeout=False,
        decode_responses=False,
    )


def guarded[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except RedisError as exc:
        raise DependencyUnavailable("redis", type(exc).__name__) from exc
