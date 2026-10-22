"""Public-plane error envelope (Ch. 43): one table from domain exceptions to HTTP.

Disclosure rules: every pre-auth token failure collapses to a uniform 401 `TOKEN_INVALID` (the
precise verifier code goes to failure aggregation, never to the caller); post-auth failures are
detailed; 5xx bodies never carry exception text, stacks, dependency names or addresses.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import JsonValue

from keystone.admin.tokens import AdminAuthFailed, AdminTokenNotFound
from keystone.api.ratelimit import RateLimited
from keystone.audit.anchor import AnchorStoreUnreachable
from keystone.authz.bundles import BundleError
from keystone.authz.evaluator import DecisionMalformed
from keystone.authz.pins import PinSequenceRejected, PolicyLoadTimeout
from keystone.authz.service import NoActivePin, PolicyPinDivergence
from keystone.broker.connectors.base import (
    AccessDeniedError,
    ConnectorError,
    IndeterminateError,
    ProtocolError,
    TemplateError,
    UnavailableError,
)
from keystone.broker.revocation import RevocationUnconfirmed
from keystone.broker.service import PolicyRegistryDivergence, TtlDenied
from keystone.db.redis import DependencyUnavailable
from keystone.identity.jwks import JwksUnavailable
from keystone.identity.oidc import TokenRejected
from keystone.registry.admin import RegistryConflict, RegistryInvalid
from keystone.registry.repo import RegistryError


@dataclass(frozen=True, slots=True)
class ApiError:
    status: int
    code: str
    message: str
    retryable: bool
    details: dict[str, JsonValue] | None = None
    retry_after_seconds: int | None = None


class RequestRejected(Exception):
    """Transport/schema validation failure (Ch. 41 layers 1-2), raised before any verification."""

    def __init__(self, error: ApiError) -> None:
        super().__init__(error.code)
        self.error = error


def rejected(status: int, code: str, message: str, **details: JsonValue) -> RequestRejected:
    return RequestRejected(ApiError(status, code, message, False, dict(details) or None))


# Most specific class first; looked up along the exception's MRO.
_STS_CODES: dict[type[ConnectorError], str] = {
    AccessDeniedError: "STS_ACCESS_DENIED",
    TemplateError: "STS_POLICY_REJECTED",
    UnavailableError: "STS_UNAVAILABLE",
    IndeterminateError: "STS_INDETERMINATE",
    ProtocolError: "STS_PROTOCOL_ERROR",
    ConnectorError: "STS_ERROR",
}

_DEPENDENCY = ApiError(
    503, "KEYSTONE_DEPENDENCY_UNAVAILABLE", "a required dependency is unavailable", True
)


KNOWN_ERRORS: tuple[type[Exception], ...] = (
    RequestRejected,
    TokenRejected,
    RateLimited,
    AnchorStoreUnreachable,
    DependencyUnavailable,
    JwksUnavailable,
    NoActivePin,
    PolicyPinDivergence,
    DecisionMalformed,
    RegistryError,
    PolicyRegistryDivergence,
    TtlDenied,
    ConnectorError,
    AdminAuthFailed,
    AdminTokenNotFound,
    BundleError,
    PinSequenceRejected,
    PolicyLoadTimeout,
    RegistryConflict,
    RegistryInvalid,
    RevocationUnconfirmed,
)


def map_exception(exc: Exception) -> ApiError:
    """The API mapping for one of KNOWN_ERRORS; anything else is a programming error."""
    match exc:
        case RequestRejected():
            return exc.error
        case TokenRejected() if exc.code == "TOKEN_REPLAYED":
            # Replay is checked after the signature, so the caller is authenticated (Ch. 17 step 9).
            return ApiError(409, "TOKEN_REPLAYED", "token has already been used", False)
        case TokenRejected():
            return ApiError(401, "TOKEN_INVALID", "token rejected", False)
        case RateLimited():
            return ApiError(
                429,
                exc.code,
                "rate limit exceeded",
                True,
                {"scope": exc.scope},
                retry_after_seconds=exc.retry_after_seconds,
            )
        case DependencyUnavailable() | JwksUnavailable():
            return _DEPENDENCY
        case AnchorStoreUnreachable():
            return ApiError(503, exc.code, "audit anchoring is unavailable; retry later", True)
        case NoActivePin() | PolicyPinDivergence():
            return ApiError(503, exc.code, "policy is not ready; retry later", True)
        case DecisionMalformed():
            return ApiError(500, exc.code, "policy decision was malformed", False)
        case RegistryError():
            # Ch. 19 post-decision validation: any policy/registry mismatch is a 500.
            return ApiError(
                500,
                "POLICY_REGISTRY_DIVERGENCE",
                "policy and role registry disagree",
                False,
                {"reason": exc.code.value},
            )
        case PolicyRegistryDivergence():
            return ApiError(500, exc.code, "policy and role registry disagree", False)
        case TtlDenied():
            return ApiError(403, TtlDenied.code, str(exc), False)
        case ConnectorError():
            code = next(_STS_CODES[c] for c in type(exc).__mro__ if c in _STS_CODES)
            return ApiError(exc.http_status, code, "credential minting failed", exc.retryable)
        case AdminAuthFailed():
            # One answer for missing/unknown/expired/revoked: no oracle for token state.
            return ApiError(401, exc.code, "admin bearer token required", False)
        case AdminTokenNotFound():
            return ApiError(404, exc.code, "no such admin token", False)
        case BundleError():
            return ApiError(400, "POLICY_BUNDLE_INVALID", str(exc), False)
        case PinSequenceRejected():
            return ApiError(409, exc.code, str(exc), False)
        case PolicyLoadTimeout():
            return ApiError(409, exc.code, str(exc), True)
        case RegistryConflict() | RegistryInvalid():
            return ApiError(exc.http_status, exc.code, str(exc), False)
        case RevocationUnconfirmed():
            # The deny policy may be on the role; the reconciler backfills revocation_applied once
            # IAM reads it back. Re-submitting would only flag a second revocation.
            return ApiError(502, "REVOCATION_UNCONFIRMED", str(exc), False)
        case _:
            raise TypeError(f"no API mapping for {type(exc).__name__}")


def envelope(error: ApiError, request_id: str) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "code": error.code,
        "message": error.message,
        "request_id": request_id,
        "retryable": error.retryable,
    }
    if error.details:
        body["details"] = error.details
    return {"error": body}
