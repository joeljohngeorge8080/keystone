"""CredentialConnector seam (Ch. 22/54) — the multi-cloud extension point. MVP: AwsStsConnector."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

ROLE_ARN_PATTERN = r"^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$"
ROLE_ARN_MAX_LEN = 2048
SESSION_NAME_PATTERN = r"^[A-Za-z0-9+=,.@_-]{2,64}$"
TAG_VALUE_PATTERN = r"^[A-Za-z0-9 _.:/=+@-]{1,256}$"
INLINE_POLICY_MAX_CHARS = 2048
ACCESS_KEY_PREFIX_LEN = 8

# Closed set of attribution tags (Ch. 22): every CloudTrail event joins back to one decision.
SESSION_TAG_KEYS = frozenset(
    {
        "keystone:decision_id",
        "keystone:repository",
        "keystone:ref",
        "keystone:workflow_ref",
        "keystone:actor",
    }
)


class ConnectorError(Exception):
    """Base for mint failures; `http_status` is the class the API maps it to (Ch. 23)."""

    http_status = 503
    retryable = False


class AccessDeniedError(ConnectorError):
    """Trust-policy or IAM-allowlist drift: registry says yes, AWS says no (502, alarm)."""

    http_status = 502


class TemplateError(ConnectorError):
    """MalformedPolicyDocument: a registry-approved template is broken (500)."""

    http_status = 500


class UnavailableError(ConnectorError):
    """Broker-credential/throttling/connect failure with NO session created (503, retryable)."""

    http_status = 503
    retryable = True


class IndeterminateError(ConnectorError):
    """Request may have reached STS: a session may exist. Never retried blindly (Ch. 23)."""

    http_status = 503


class ProtocolError(ConnectorError):
    """STS answered with something the broker's invariants do not allow (500)."""

    http_status = 500


class MintRequest(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    role_arn: str = Field(pattern=ROLE_ARN_PATTERN, max_length=ROLE_ARN_MAX_LEN)
    session_name: str = Field(pattern=SESSION_NAME_PATTERN)
    duration_seconds: int = Field(ge=900, le=3600)
    session_policy: dict[str, JsonValue] | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    external_id: str | None = Field(default=None, min_length=2, max_length=1224)

    @field_validator("session_policy")
    @classmethod
    def _policy_fits_sts_limit(
        cls, value: dict[str, JsonValue] | None
    ) -> dict[str, JsonValue] | None:
        if (
            value is not None
            and len(json.dumps(value, separators=(",", ":"))) > INLINE_POLICY_MAX_CHARS
        ):
            raise ValueError(f"inline session policy exceeds {INLINE_POLICY_MAX_CHARS} chars")
        return value

    @field_validator("tags")
    @classmethod
    def _tags_from_closed_set(cls, value: dict[str, str]) -> dict[str, str]:
        import re

        for key, tag_value in value.items():
            if key not in SESSION_TAG_KEYS:
                raise ValueError(f"tag {key!r} is not in the keystone attribution set")
            if not re.fullmatch(TAG_VALUE_PATTERN, tag_value):
                raise ValueError(f"tag {key!r} has a value outside the allowed charset/length")
        return value


@dataclass(frozen=True, slots=True, repr=False)
class IssuedCredential:
    """Opaque minted credential. Never logged, never persisted (Ch. 24 cardinal invariant)."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime

    @property
    def access_key_prefix(self) -> str:
        return self.access_key_id[:ACCESS_KEY_PREFIX_LEN]

    def __repr__(self) -> str:
        expires = self.expiration.isoformat()
        return f"IssuedCredential(prefix={self.access_key_prefix}, expiration={expires})"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class ConnectorCapabilities:
    provider: str
    max_duration_seconds: int
    supports_session_policy: bool
    supports_tags: bool
    supports_external_id: bool


class CredentialConnector(Protocol):
    def mint(self, request: MintRequest) -> IssuedCredential: ...

    def describe_capabilities(self) -> ConnectorCapabilities: ...

    def validate_registration(self, role_arn: str, external_id: str | None) -> None: ...
