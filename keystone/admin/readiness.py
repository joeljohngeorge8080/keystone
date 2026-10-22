"""`/readyz` (Ch. 53): can this instance complete the issuance path right now?

Checks PostgreSQL, Redis, OPA's loaded bundle against the committed pin (R5 divergence), the
anchor breaker (R7) and JWKS fresh-or-grace. Every degraded state is enumerated by name so
traffic control can act on it; the body carries states only, never digests or addresses.
Clock-sync (NTP) is not probed yet.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import redis
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from keystone.audit.anchor import AnchorBreaker, AnchorStoreUnreachable
from keystone.authz.pins import BundleGateway
from keystone.authz.service import active_pin
from keystone.db.redis import DependencyUnavailable, guarded
from keystone.identity.jwks import JwksCache

OK = "ok"


@dataclass(frozen=True, slots=True)
class Readiness:
    checks: dict[str, str] = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return all(state in (OK, "fresh", "grace") for state in self.checks.values())

    @property
    def degraded(self) -> list[str]:
        return sorted(
            name for name, state in self.checks.items() if state not in (OK, "fresh", "grace")
        )


class ReadinessProbe:
    def __init__(
        self,
        engine: Engine,
        client: redis.Redis,
        gateway: BundleGateway,
        jwks: JwksCache,
        breaker: AnchorBreaker,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._engine = engine
        self._redis = client
        self._gateway = gateway
        self._jwks = jwks
        self._breaker = breaker
        self._clock = clock

    def check(self) -> Readiness:
        checks: dict[str, str] = {}
        pin_digest: str | None = None
        try:
            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                pin = active_pin(conn)
            checks["postgres"] = OK
            pin_digest = pin.bundle_digest if pin else None
        except SQLAlchemyError:
            checks["postgres"] = "unreachable"
        try:
            guarded(self._redis.ping)
            checks["redis"] = OK
        except DependencyUnavailable:
            checks["redis"] = "unreachable"
        checks["policy"] = self._policy(pin_digest, postgres_ok=checks["postgres"] == OK)
        if checks["redis"] == OK:
            checks["anchor_breaker"] = self._anchor()
            checks["jwks"] = self._jwks_state()
        else:
            checks["anchor_breaker"] = checks["jwks"] = "unknown"
        return Readiness(checks)

    def _policy(self, pin_digest: str | None, *, postgres_ok: bool) -> str:
        if not postgres_ok:
            return "unknown"
        if pin_digest is None:
            return "no_active_pin"
        loaded = self._gateway.loaded_digest()  # None on OPA error or no single bundle loaded
        if loaded is None:
            return "opa_unavailable"
        return OK if loaded == pin_digest else "divergent"

    def _anchor(self) -> str:
        try:
            self._breaker.check(self._clock())
        except AnchorStoreUnreachable:
            return "open"
        except DependencyUnavailable:
            return "unknown"
        return OK

    def _jwks_state(self) -> str:
        try:
            return self._jwks.freshness()
        except DependencyUnavailable:
            return "unknown"
