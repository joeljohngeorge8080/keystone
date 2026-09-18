"""Target-role registry models (Ch. 22) — the PostgreSQL half of the double allowlist."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from keystone.broker.connectors.base import ROLE_ARN_MAX_LEN, ROLE_ARN_PATTERN

NAME_PATTERN = r"^[a-z0-9][a-z0-9-]{1,63}$"


class TargetRole(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    id: uuid.UUID
    name: str = Field(pattern=NAME_PATTERN)
    role_arn: str = Field(pattern=ROLE_ARN_PATTERN, max_length=ROLE_ARN_MAX_LEN)
    max_ttl_seconds: int = Field(ge=900, le=3600)
    external_id: str | None = None
    enabled: bool
    description: str = ""
    owner: str = ""


class SessionPolicyTemplate(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    id: uuid.UUID
    target_role_id: uuid.UUID
    ref: str = Field(pattern=NAME_PATTERN)
    policy_document: dict[str, JsonValue]
    enabled: bool
