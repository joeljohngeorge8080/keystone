"""Issuance state machine + repository — spec Ch. 24 (AMB-3: denials write no row)."""

from __future__ import annotations

import enum
import json
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, JsonValue
from sqlalchemy import text
from sqlalchemy.engine import Connection

from keystone.broker.connectors.base import SESSION_NAME_PATTERN
from keystone.db.ids import uuid7
from keystone.registry.models import NAME_PATTERN


class IssuanceState(enum.StrEnum):
    REQUESTED = "requested"
    AUTHORIZED = "authorized"
    ISSUED = "issued"
    DELIVERED = "delivered"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


TERMINAL_STATES = frozenset({IssuanceState.DELIVERED, IssuanceState.FAILED})

# Edges from the Ch. 24 diagram plus R6 (indeterminate resolves to issued or failed).
TRANSITIONS: dict[IssuanceState, frozenset[IssuanceState]] = {
    IssuanceState.REQUESTED: frozenset({IssuanceState.AUTHORIZED}),
    IssuanceState.AUTHORIZED: frozenset(
        {IssuanceState.ISSUED, IssuanceState.FAILED, IssuanceState.INDETERMINATE}
    ),
    IssuanceState.ISSUED: frozenset({IssuanceState.DELIVERED}),
    IssuanceState.INDETERMINATE: frozenset({IssuanceState.ISSUED, IssuanceState.FAILED}),
    IssuanceState.DELIVERED: frozenset(),
    IssuanceState.FAILED: frozenset(),
}


class IllegalTransition(Exception):
    pass


class Issuance(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    id: uuid.UUID
    jti_hash: bytes = Field(min_length=32, max_length=32)
    target_role_id: uuid.UUID
    policy_pin_id: uuid.UUID
    state: IssuanceState
    grant_name: str = Field(pattern=NAME_PATTERN)
    session_name: str = Field(pattern=SESSION_NAME_PATTERN)
    session_policy_ref: str | None
    access_key_prefix: str | None
    granted_ttl_seconds: int = Field(ge=900, le=3600)
    expires_at: datetime | None
    identity_claims: dict[str, JsonValue]


_COLUMNS = (
    "id, jti_hash, target_role_id, policy_pin_id, state, grant_name, session_name, "
    "session_policy_ref, access_key_prefix, granted_ttl_seconds, expires_at, identity_claims"
)
_INSERT = text(
    f"INSERT INTO issuances ({_COLUMNS}) VALUES (:id, :jti_hash, :target_role_id, "  # noqa: S608
    ":policy_pin_id, :state, :grant_name, :session_name, :session_policy_ref, "
    ":access_key_prefix, :granted_ttl_seconds, :expires_at, CAST(:identity_claims AS jsonb))"
)
_GET = text(f"SELECT {_COLUMNS} FROM issuances WHERE id = :id")  # noqa: S608
_TRANSITION = text(
    "UPDATE issuances SET state = :to_state, "
    "access_key_prefix = COALESCE(:access_key_prefix, access_key_prefix), "
    "expires_at = COALESCE(:expires_at, expires_at), updated_at = now() "
    "WHERE id = :id AND state = :from_state"
)
_NON_TERMINAL = text(
    f"SELECT {_COLUMNS} FROM issuances "  # noqa: S608
    "WHERE state IN ('authorized', 'issued', 'indeterminate') ORDER BY created_at"
)


def _row_to_issuance(row: object) -> Issuance:
    mapping = dict(row._mapping)  # type: ignore[attr-defined]
    mapping["jti_hash"] = bytes(mapping["jti_hash"])
    mapping["state"] = IssuanceState(mapping["state"])
    return Issuance(**mapping)


class IssuanceRepository:
    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def create_authorized(
        self,
        *,
        jti_hash: bytes,
        target_role_id: uuid.UUID,
        policy_pin_id: uuid.UUID,
        grant_name: str,
        session_name: str,
        session_policy_ref: str | None,
        granted_ttl_seconds: int,
        identity_claims: dict[str, JsonValue],
    ) -> Issuance:
        issuance = Issuance(
            id=uuid7(),
            jti_hash=jti_hash,
            target_role_id=target_role_id,
            policy_pin_id=policy_pin_id,
            state=IssuanceState.AUTHORIZED,
            grant_name=grant_name,
            session_name=session_name,
            session_policy_ref=session_policy_ref,
            access_key_prefix=None,
            granted_ttl_seconds=granted_ttl_seconds,
            expires_at=None,
            identity_claims=identity_claims,
        )
        params = issuance.model_dump()
        params["state"] = issuance.state.value
        params["identity_claims"] = json.dumps(identity_claims, separators=(",", ":"))
        self._conn.execute(_INSERT, params)
        return issuance

    def get(self, issuance_id: uuid.UUID) -> Issuance | None:
        row = self._conn.execute(_GET, {"id": issuance_id}).one_or_none()
        return None if row is None else _row_to_issuance(row)

    def transition(
        self,
        issuance_id: uuid.UUID,
        from_state: IssuanceState,
        to_state: IssuanceState,
        *,
        access_key_prefix: str | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        if to_state not in TRANSITIONS[from_state]:
            raise IllegalTransition(f"{from_state} -> {to_state} is not a legal edge")
        result = self._conn.execute(
            _TRANSITION,
            {
                "id": issuance_id,
                "from_state": from_state.value,
                "to_state": to_state.value,
                "access_key_prefix": access_key_prefix,
                "expires_at": expires_at,
            },
        )
        if result.rowcount != 1:
            raise IllegalTransition(f"issuance {issuance_id} is not in state {from_state}")

    def non_terminal(self) -> list[Issuance]:
        return [_row_to_issuance(row) for row in self._conn.execute(_NON_TERMINAL)]
