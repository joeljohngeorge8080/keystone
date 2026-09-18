"""Audit event model and its canonical (hashed) object form — spec Ch. 32/33, R1."""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

SCHEMA_VERSION = 1


class EventType(enum.StrEnum):
    AUTH_FAILED = "auth_failed"
    TOKEN_REPLAYED = "token_replayed"  # noqa: S105 — event label, not a secret
    RATE_LIMITED = "rate_limited"
    PRE_AUTH_SHED = "pre_auth_shed"
    DECISION_DENIED = "decision_denied"
    DECISION_ALLOWED = "decision_allowed"
    CREDENTIAL_ISSUED = "credential_issued"
    CREDENTIAL_ISSUE_FAILED = "credential_issue_failed"
    STS_INDETERMINATE = "sts_indeterminate"
    ISSUED_UNDELIVERED = "issued_undelivered"
    ADMIN_POLICY_PINNED = "admin_policy_pinned"
    ADMIN_POLICY_ROLLBACK = "admin_policy_rollback"
    ADMIN_ROLE_CHANGED = "admin_role_changed"
    ADMIN_TOKEN_ISSUED = "admin_token_issued"  # noqa: S105 — event label, not a secret
    ADMIN_TOKEN_REVOKED = "admin_token_revoked"  # noqa: S105
    REVOCATION_FLAGGED = "revocation_flagged"
    REVOCATION_APPLIED = "revocation_applied"
    RETENTION_PRUNED = "retention_pruned"
    ANCHOR_WRITTEN = "anchor_written"


# No-stored-credentials invariant (Ch. 24/48): these keys can never enter the audit record.
FORBIDDEN_DATA_KEYS: frozenset[str] = frozenset(
    {
        "accesskeyid",
        "secretaccesskey",
        "sessiontoken",
        "authorization",
        "id_token",
        "token",
        "private_key",
    }
)


def _normalize_key(key: str) -> str:
    return key.replace("_", "").replace("-", "").lower()


def assert_no_forbidden_keys(value: JsonValue, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if _normalize_key(key) in {_normalize_key(k) for k in FORBIDDEN_DATA_KEYS}:
                raise ValueError(f"forbidden key {key!r} at {path or '$'}")
            assert_no_forbidden_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            assert_no_forbidden_keys(child, f"{path}[{i}]")


def format_rfc3339(moment: datetime) -> str:
    """Fixed-precision UTC RFC 3339 so the canonical form is byte-deterministic."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AuditEventInput(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    event_type: EventType
    occurred_at: datetime
    actor: str = Field(min_length=1, max_length=256)
    issuance_id: uuid.UUID | None = None
    admin_principal_id: uuid.UUID | None = None
    input_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    policy_digest: str | None = Field(default=None, min_length=1, max_length=128)
    data: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def _must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("occurred_at must be timezone-aware UTC")
        return value

    @field_validator("data")
    @classmethod
    def _no_secret_material(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        assert_no_forbidden_keys(value)
        return value


def canonical_object(seq: int, event_id: uuid.UUID, event: AuditEventInput) -> dict[str, JsonValue]:
    """The exact object that is JCS-canonicalized and hashed; `details JSONB` is its projection."""
    return {
        "schema_version": SCHEMA_VERSION,
        "seq": seq,
        "id": str(event_id),
        "event_type": event.event_type.value,
        "occurred_at": format_rfc3339(event.occurred_at),
        "actor": event.actor,
        "issuance_id": None if event.issuance_id is None else str(event.issuance_id),
        "admin_principal_id": (
            None if event.admin_principal_id is None else str(event.admin_principal_id)
        ),
        "input_hash": event.input_hash,
        "policy_digest": event.policy_digest,
        "data": event.data,
    }
