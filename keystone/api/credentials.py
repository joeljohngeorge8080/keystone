"""`POST /v1/credentials` pipeline (Ch. 39-43): Tier 0 -> verify -> Tier 1 -> anchor breaker ->
authorize -> STS slot -> issue.

Framework-free on purpose: `app.py` owns transport (body cap, content type, envelope) and calls
`handle()` in a worker thread. Pre-decision failures are counted by the bounded aggregator (R4),
never written one row per request; decisions and issuance outcomes are chained by the stages
that own them. The caller marks DELIVERED only after the single-shot response is sent.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from keystone.api.ratelimit import RateLimited, StsInflightGuard, Tier0Shedder, Tier1Limiter
from keystone.audit.aggregation import AggregatedFailure, FailureAggregator
from keystone.audit.anchor import AnchorBreaker
from keystone.authz.service import AuthorizationService, Denied
from keystone.broker.service import IdentityContext, IssuanceService
from keystone.db.ids import uuid7
from keystone.identity.oidc import MAX_TOKEN_BYTES, IssuerVerifier, TokenRejected, VerifiedIdentity

TOKEN_PATTERN = r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"  # noqa: S105 — JWT shape
GRANT_PATTERN = r"^[a-z0-9][a-z0-9-]{1,63}$"
PRE_AUTH_KEY = "unauthenticated"  # coarse aggregation key: nothing about the caller is verified


class CredentialRequest(BaseModel):
    """Ch. 41 layer 2. The token is excluded from repr so it can never reach a log line."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    token: str = Field(max_length=MAX_TOKEN_BYTES, pattern=TOKEN_PATTERN, repr=False)
    grant: str = Field(pattern=GRANT_PATTERN)
    ttl_seconds: int | None = Field(default=None, ge=1, le=86400)


class Credentials(BaseModel):
    model_config = ConfigDict(frozen=True)

    access_key_id: str
    secret_access_key: str = Field(repr=False)
    session_token: str = Field(repr=False)
    expiration: str


class CredentialResponse(BaseModel):
    """Ch. 42 issuance 201 body."""

    model_config = ConfigDict(frozen=True)

    request_id: str
    decision_id: uuid.UUID
    grant: str
    credentials: Credentials
    granted_ttl_seconds: int
    ttl_clamped: bool
    region_hint: str
    audit_seq: int


@dataclass(frozen=True, slots=True)
class Issued:
    response: CredentialResponse
    issuance_id: uuid.UUID


class CredentialHandler(Protocol):
    """What the HTTP layer needs; `CredentialPipeline` is the production implementation."""

    def handle(
        self, request: CredentialRequest, *, source_ip: str, request_id: str
    ) -> Issued | Denied: ...

    def mark_delivered(self, issuance_id: uuid.UUID) -> None: ...


def identity_context(identity: VerifiedIdentity) -> IdentityContext:
    return IdentityContext(
        jti_hash=identity.jti_hash,
        actor=identity.actor,
        repository=identity.repository,
        repository_id=identity.repository_id,
        run_id=identity.run_id,
        ref=identity.ref,
        workflow_ref=identity.workflow_ref,
        claims=dict(identity.claims),
    )


def _subject_key(sub: str) -> str:
    # `sub` is attacker-influenced and may contain the aggregator's '|' separator.
    return "sub:" + hashlib.sha256(sub.encode("utf-8")).hexdigest()


class CredentialPipeline:
    def __init__(
        self,
        *,
        shedder: Tier0Shedder,
        verifier: IssuerVerifier,
        limiter: Tier1Limiter,
        authorizer: AuthorizationService,
        sts_slots: StsInflightGuard,
        issuer: IssuanceService,
        aggregator: FailureAggregator,
        breaker: AnchorBreaker,
        region_hint: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._shedder = shedder
        self._verifier = verifier
        self._limiter = limiter
        self._authorizer = authorizer
        self._sts_slots = sts_slots
        self._issuer = issuer
        self._aggregator = aggregator
        self._breaker = breaker
        self._region_hint = region_hint
        self._clock = clock

    def handle(
        self, request: CredentialRequest, *, source_ip: str, request_id: str
    ) -> Issued | Denied:
        decision_id = uuid7()  # exists before verification: the replay record points at it
        try:
            self._shedder.check()
        except RateLimited as exc:
            self._aggregator.record(AggregatedFailure.PRE_AUTH_SHED, PRE_AUTH_KEY, exc.code)
            raise
        try:
            identity = self._verifier.verify(request.token, decision_id=decision_id)
        except TokenRejected as exc:
            failure = (
                AggregatedFailure.TOKEN_REPLAYED
                if exc.code == "TOKEN_REPLAYED"
                else AggregatedFailure.AUTH_FAILED
            )
            self._aggregator.record(failure, PRE_AUTH_KEY, exc.code)
            raise
        try:
            self._limiter.check(sub=identity.sub, repository_id=identity.repository_id)
        except RateLimited as exc:
            self._aggregator.record(
                AggregatedFailure.RATE_LIMITED, _subject_key(identity.sub), exc.code
            )
            raise
        # R7: while the external anchor store is unreachable past the threshold, the
        # un-anchored window must not grow, so nothing is decided or minted.
        self._breaker.check(self._clock())
        outcome = self._authorizer.authorize(
            identity,
            grant=request.grant,
            requested_ttl_seconds=request.ttl_seconds,
            source_ip=source_ip,
            decision_id=decision_id,
        )
        if isinstance(outcome, Denied):
            return outcome
        try:
            with self._sts_slots.slot():
                result = self._issuer.issue(
                    outcome, identity_context(identity), request.ttl_seconds
                )
        except RateLimited as exc:
            self._aggregator.record(
                AggregatedFailure.RATE_LIMITED, _subject_key(identity.sub), exc.code
            )
            raise
        credential = result.credential
        return Issued(
            response=CredentialResponse(
                request_id=request_id,
                decision_id=outcome.decision_id,
                grant=outcome.grant,
                credentials=Credentials(
                    access_key_id=credential.access_key_id,
                    secret_access_key=credential.secret_access_key,
                    session_token=credential.session_token,
                    expiration=credential.expiration.astimezone(UTC).isoformat(),
                ),
                granted_ttl_seconds=result.granted_ttl_seconds,
                ttl_clamped=result.ttl_clamped,
                region_hint=self._region_hint,
                audit_seq=result.audit_seq,
            ),
            issuance_id=result.issuance.id,
        )

    def mark_delivered(self, issuance_id: uuid.UUID) -> None:
        self._issuer.mark_delivered(issuance_id)
