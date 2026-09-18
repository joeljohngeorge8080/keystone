"""GitHub Actions OIDC verification (Ch. 16-17, 31): cheapest-first, every step mandatory.

Order: structure -> alg allowlist -> configured issuer -> kid/JWKS -> RS256 signature -> temporal
with one request-scoped `now` and +-60 s skew -> audience -> required claims -> JTI replay.
The raw token exists only inside `verify()`; it is never stored, logged, or put in an error.
"""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from keystone.identity.jwks import JwksCache, KidUnknown
from keystone.identity.replay import ReplayStore, jti_hash, replay_ttl_ms

MAX_TOKEN_BYTES = 16 * 1024
SKEW_SECONDS = 60
IAT_MAX_AGE_SECONDS = 900
ALLOWED_ALGORITHMS = ("RS256",)

STRING_CLAIMS = (
    "sub",
    "repository",
    "repository_owner",
    "repository_id",
    "ref",
    "sha",
    "workflow_ref",
    "job_workflow_ref",
    "run_id",
    "run_attempt",
    "actor",
    "event_name",
    "jti",
)
INT_CLAIMS = ("iat", "exp", "nbf")


class TokenRejected(Exception):
    """Any verification failure. Messages are generic on purpose (uniform 401, Ch. 43)."""

    def __init__(self, code: str, http_status: int = 401) -> None:
        super().__init__(code)
        self.code = code
        self.http_status = http_status


class VerifiedIdentity(BaseModel):
    """The only object the authorization layer accepts (Ch. 16). Claims are passed verbatim."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    sub: str
    repository: str
    repository_owner: str
    repository_id: str
    ref: str
    workflow_ref: str
    run_id: str
    actor: str
    event_name: str
    jti_hash: bytes = Field(min_length=32, max_length=32)
    kid: str
    issued_at: datetime
    expires_at: datetime
    verified_at: datetime
    claims: dict[str, JsonValue]


class IssuerVerifier(Protocol):
    """Extension point keyed by issuer (GitLab/Jenkins later)."""

    def verify(self, token: str, *, decision_id: uuid.UUID) -> VerifiedIdentity: ...


def _b64url_json(segment: str) -> dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(decoded)
    except (ValueError, UnicodeError) as exc:
        raise TokenRejected("TOKEN_MALFORMED") from exc
    if not isinstance(parsed, dict):
        raise TokenRejected("TOKEN_MALFORMED")
    return parsed


class GitHubOidcVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks: JwksCache,
        replay: ReplayStore,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not issuer.startswith("https://") or not audience:
            raise ValueError("issuer must be https and audience non-empty (A5)")
        self._issuer = issuer
        self._audience = audience
        self._jwks = jwks
        self._replay = replay
        self._clock = clock

    def verify(self, token: str, *, decision_id: uuid.UUID) -> VerifiedIdentity:
        now = self._clock()  # single request-scoped now (Ch. 31)
        header, unverified_payload = self._structural(token)
        self._pre_crypto(header, unverified_payload)
        kid = header["kid"]
        try:
            key = self._jwks.resolve(kid)
        except KidUnknown as exc:
            raise TokenRejected("TOKEN_KID_UNKNOWN") from exc
        claims = self._signature(token, key)
        self._temporal(claims, now)
        self._audience_check(claims)
        self._required_claims(claims)
        if claims.get("iss") != self._issuer:
            raise TokenRejected("TOKEN_ISSUER_REJECTED")
        digest = jti_hash(claims["jti"])
        expires_at = datetime.fromtimestamp(claims["exp"], tz=UTC)
        if not self._replay.consume(digest, decision_id, replay_ttl_ms(expires_at, now)):
            raise TokenRejected("TOKEN_REPLAYED", http_status=409)
        return VerifiedIdentity(
            sub=claims["sub"],
            repository=claims["repository"],
            repository_owner=claims["repository_owner"],
            repository_id=claims["repository_id"],
            ref=claims["ref"],
            workflow_ref=claims["workflow_ref"],
            run_id=claims["run_id"],
            actor=claims["actor"],
            event_name=claims["event_name"],
            jti_hash=digest,
            kid=kid,
            issued_at=datetime.fromtimestamp(claims["iat"], tz=UTC),
            expires_at=expires_at,
            verified_at=now,
            claims=claims,
        )

    # ---- steps ----

    @staticmethod
    def _structural(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        if not token or len(token.encode("utf-8", errors="replace")) > MAX_TOKEN_BYTES:
            raise TokenRejected("TOKEN_MALFORMED")
        parts = token.split(".")
        if len(parts) != 3 or not all(parts[:2]):
            raise TokenRejected("TOKEN_MALFORMED")
        return _b64url_json(parts[0]), _b64url_json(parts[1])

    def _pre_crypto(self, header: dict[str, Any], payload: dict[str, Any]) -> None:
        if header.get("alg") not in ALLOWED_ALGORITHMS or "crit" in header:
            raise TokenRejected("TOKEN_ALG_REJECTED")
        if payload.get("iss") != self._issuer:
            raise TokenRejected("TOKEN_ISSUER_REJECTED")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > 256:
            raise TokenRejected("TOKEN_KID_UNKNOWN")

    @staticmethod
    def _signature(token: str, key: RSAPublicKey) -> dict[str, Any]:
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=list(ALLOWED_ALGORITHMS),
                options={
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except jwt.exceptions.InvalidTokenError as exc:
            raise TokenRejected("TOKEN_SIGNATURE_INVALID") from exc
        return claims

    @staticmethod
    def _temporal(claims: dict[str, Any], now: datetime) -> None:
        now_ts = int(now.timestamp())
        for name in INT_CLAIMS:
            value = claims.get(name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TokenRejected("TOKEN_CLAIMS_INCOMPLETE")
        if claims["exp"] + SKEW_SECONDS <= now_ts:
            raise TokenRejected("TOKEN_EXPIRED")
        if claims["nbf"] - SKEW_SECONDS > now_ts:
            raise TokenRejected("TOKEN_NOT_YET_VALID")
        if claims["iat"] > now_ts + SKEW_SECONDS or claims["iat"] < now_ts - IAT_MAX_AGE_SECONDS:
            raise TokenRejected("TOKEN_IAT_INVALID")

    def _audience_check(self, claims: dict[str, Any]) -> None:
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if self._audience not in [a for a in audiences if isinstance(a, str)]:
            raise TokenRejected("TOKEN_AUDIENCE_REJECTED")

    @staticmethod
    def _required_claims(claims: dict[str, Any]) -> None:
        for name in STRING_CLAIMS:
            value = claims.get(name)
            if not isinstance(value, str) or not value or len(value) > 1024:
                raise TokenRejected("TOKEN_CLAIMS_INCOMPLETE")
