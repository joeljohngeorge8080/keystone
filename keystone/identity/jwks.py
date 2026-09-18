"""Three-tier JWKS cache (Ch. 18): in-process 5 min -> Redis 15 min -> origin (3 s, single-flight).

Poison resistance: only RSA >= 2048-bit signing keys are accepted, documents over 64 KiB or that
fail to parse never overwrite a valid cache. On origin failure a warm cache is served stale for up
to 6 h, then the path fails closed (503). Redis unreachable is a 503 everywhere (F11).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

import httpx
import redis
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt import PyJWK
from jwt.exceptions import PyJWKError

from keystone.db.redis import guarded

MAX_JWKS_BYTES = 64 * 1024
MIN_RSA_BITS = 2048
IN_PROCESS_TTL_SECONDS = 300
REDIS_FRESH_SECONDS = 900
STALE_CEILING_SECONDS = 6 * 3600
FORCED_REFRESH_MIN_INTERVAL_SECONDS = 60
ORIGIN_TIMEOUT_SECONDS = 3.0
SINGLE_FLIGHT_LOCK_MS = 5000

_RAW_KEY = "jwks:raw"
_FRESH_UNTIL_KEY = "jwks:fresh_until"
_LOCK_KEY = "jwks:lock"
_REFRESH_GATE_KEY = "jwks:refresh_gate"


class KidUnknown(Exception):
    http_status = 401
    code = "TOKEN_KID_UNKNOWN"


class JwksUnavailable(Exception):
    http_status = 503
    code = "JWKS_UNAVAILABLE"


class JwksSource(Protocol):
    def fetch(self) -> bytes: ...


class HttpJwksSource:
    """Configured URL, never discovered from the token (SSRF / issuer-confusion vector, Ch. 17)."""

    def __init__(self, url: str, *, client: httpx.Client | None = None) -> None:
        if not url.startswith("https://"):
            raise ValueError("JWKS origin must be https")
        self._url = url
        self._client = client or httpx.Client(
            timeout=ORIGIN_TIMEOUT_SECONDS, follow_redirects=False
        )

    def fetch(self) -> bytes:
        try:
            response = self._client.get(self._url, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise JwksUnavailable(f"origin fetch failed: {type(exc).__name__}") from exc
        if response.status_code != 200:
            raise JwksUnavailable(f"origin returned {response.status_code}")
        if len(response.content) > MAX_JWKS_BYTES:
            raise JwksUnavailable("origin document exceeds size cap")
        return response.content


def parse_jwks(raw: bytes) -> dict[str, RSAPublicKey]:
    """Strict parse: returns kid -> RSA public key, or raises ValueError. Never partial-trusts."""
    if len(raw) > MAX_JWKS_BYTES:
        raise ValueError("JWKS document exceeds 64 KiB")
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise ValueError("JWKS is not valid JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("JWKS has no keys array")
    keys: dict[str, RSAPublicKey] = {}
    for entry in document["keys"]:
        if not isinstance(entry, dict):
            continue
        if entry.get("kty") != "RSA" or entry.get("use", "sig") != "sig":
            continue
        if entry.get("alg", "RS256") != "RS256":
            continue
        kid = entry.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        try:
            public = PyJWK(entry, algorithm="RS256").key
        except (PyJWKError, ValueError, TypeError):
            continue
        if not isinstance(public, RSAPublicKey) or public.key_size < MIN_RSA_BITS:
            continue
        keys[kid] = public
    if not keys:
        raise ValueError("JWKS contains no usable RS256 keys")
    return keys


@dataclass(slots=True)
class _InProcess:
    keys: dict[str, RSAPublicKey]
    expires_at: float


class JwksCache:
    def __init__(
        self,
        client: redis.Redis,
        source: JwksSource,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._redis = client
        self._source = source
        self._clock = clock
        self._sleep = sleep
        self._local: _InProcess | None = None
        self.origin_fetches = 0
        self.served_stale = False

    # ---- public ----

    def resolve(self, kid: str) -> RSAPublicKey:
        keys = self._keys()
        if kid in keys:
            return keys[kid]
        # Rotation: one forced refresh, rate-limited to once per 60 s across the fleet (Ch. 18).
        if self._acquire_refresh_gate():
            self._local = None
            keys = self._keys(force_refresh=True)
            if kid in keys:
                return keys[kid]
        raise KidUnknown(f"kid {kid!r} not in JWKS")

    def prefetch(self) -> None:
        """Worker hook (Ch. 18): refresh every 5 min so the hot path rarely goes to origin."""
        self._local = None
        self._keys(force_refresh=True)

    # ---- tiers ----

    def _now(self) -> float:
        return self._clock().timestamp()

    def _keys(self, *, force_refresh: bool = False) -> dict[str, RSAPublicKey]:
        now = self._now()
        if not force_refresh and self._local and self._local.expires_at > now:
            return self._local.keys
        raw = self._redis_tier(now, force_refresh=force_refresh)
        keys = parse_jwks(raw)
        self._local = _InProcess(keys=keys, expires_at=now + IN_PROCESS_TTL_SECONDS)
        return keys

    def _redis_tier(self, now: float, *, force_refresh: bool) -> bytes:
        raw = cast(bytes | None, guarded(lambda: self._redis.get(_RAW_KEY)))
        fresh_until_raw = cast(bytes | None, guarded(lambda: self._redis.get(_FRESH_UNTIL_KEY)))
        fresh_until = float(fresh_until_raw) if fresh_until_raw else 0.0
        if raw is not None and not force_refresh and fresh_until > now:
            self.served_stale = False
            return raw
        try:
            return self._origin_tier(now)
        except JwksUnavailable:
            if raw is not None:
                # Warm but expired-fresh cache: serve stale within the 6 h ceiling (Redis TTL).
                self.served_stale = True
                return raw
            raise

    def _origin_tier(self, now: float) -> bytes:
        locked = guarded(
            lambda: self._redis.set(_LOCK_KEY, b"1", nx=True, px=SINGLE_FLIGHT_LOCK_MS)
        )
        if not locked:
            return self._wait_for_other_fetcher(now)
        try:
            raw = self._source.fetch()
            parse_jwks(raw)  # invalid documents never overwrite a valid cache
            self.origin_fetches += 1
            fresh_until = str(now + REDIS_FRESH_SECONDS).encode("ascii")

            def store() -> None:
                pipe = self._redis.pipeline()
                pipe.set(_RAW_KEY, raw, ex=STALE_CEILING_SECONDS)
                pipe.set(_FRESH_UNTIL_KEY, fresh_until, ex=STALE_CEILING_SECONDS)
                pipe.execute()

            guarded(store)
            self.served_stale = False
            return raw
        except ValueError as exc:
            raise JwksUnavailable(f"origin returned an unusable JWKS: {exc}") from exc
        finally:
            guarded(lambda: self._redis.delete(_LOCK_KEY))

    def _wait_for_other_fetcher(self, now: float) -> bytes:
        deadline = time.monotonic() + ORIGIN_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            self._sleep(0.05)
            fresh_until_raw = cast(bytes | None, guarded(lambda: self._redis.get(_FRESH_UNTIL_KEY)))
            if fresh_until_raw and float(fresh_until_raw) > now:
                raw = cast(bytes | None, guarded(lambda: self._redis.get(_RAW_KEY)))
                if raw is not None:
                    return raw
            if not guarded(lambda: self._redis.exists(_LOCK_KEY)):
                break
        raw = cast(bytes | None, guarded(lambda: self._redis.get(_RAW_KEY)))
        if raw is not None:
            return raw
        raise JwksUnavailable("no JWKS available while another fetch was in flight")

    def _acquire_refresh_gate(self) -> bool:
        return bool(
            guarded(
                lambda: self._redis.set(
                    _REFRESH_GATE_KEY, b"1", nx=True, ex=FORCED_REFRESH_MIN_INTERVAL_SECONDS
                )
            )
        )
