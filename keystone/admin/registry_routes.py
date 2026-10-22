"""Registry and revocation routes (Ch. 22, 26, 40): every mutation is audited by the service."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Path, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator
from starlette.concurrency import run_in_threadpool

from keystone.admin.deps import Admin, Services, actor_of
from keystone.api.errors import rejected
from keystone.api.http import json_response, read_json
from keystone.broker.connectors.base import ROLE_ARN_MAX_LEN, ROLE_ARN_PATTERN
from keystone.registry.models import NAME_PATTERN, SessionPolicyTemplate, TargetRole

MAX_JSON_BYTES = 32 * 1024
NOT_BEFORE_FUTURE_SKEW = timedelta(seconds=60)

RoleName = Annotated[str, Path(pattern=NAME_PATTERN)]

router = APIRouter()


class RoleCreate(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    name: str = Field(pattern=NAME_PATTERN)
    role_arn: str = Field(pattern=ROLE_ARN_PATTERN, max_length=ROLE_ARN_MAX_LEN)
    max_ttl_seconds: int = Field(ge=900, le=3600)
    description: str = Field(default="", max_length=512)
    owner: str = Field(default="", max_length=256)


class RolePatch(BaseModel):
    """`role_arn` is not patchable; see RoleRegistry.update_role."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    max_ttl_seconds: int | None = Field(default=None, ge=900, le=3600)
    enabled: bool | None = None
    description: str | None = Field(default=None, max_length=512)
    owner: str | None = Field(default=None, max_length=256)


class TemplateCreate(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    ref: str = Field(pattern=NAME_PATTERN)
    policy_document: dict[str, JsonValue]


class RevocationRequest(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    role: str = Field(pattern=NAME_PATTERN)
    # RFC 3339 string in the body; strict mode would refuse a str for a datetime.
    not_before: datetime | None = Field(default=None, strict=False)

    @field_validator("not_before")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("not_before must carry a timezone")
        return value


def role_json(role: TargetRole) -> dict[str, JsonValue]:
    return {
        "name": role.name,
        "role_arn": role.role_arn,
        "max_ttl_seconds": role.max_ttl_seconds,
        "enabled": role.enabled,
        "description": role.description,
        "owner": role.owner,
    }


def template_json(template: SessionPolicyTemplate) -> dict[str, JsonValue]:
    return {
        "ref": template.ref,
        "policy_document": template.policy_document,
        "enabled": template.enabled,
    }


@router.get("/v1/roles")
def list_roles(_: Admin, services: Services) -> dict[str, JsonValue]:
    return {"roles": [role_json(r) for r in services.registry.list_roles()]}


@router.post("/v1/roles")
async def create_role(request: Request, principal: Admin, services: Services) -> JSONResponse:
    body = await read_json(request, RoleCreate, max_bytes=MAX_JSON_BYTES)
    role = await run_in_threadpool(
        services.registry.create_role,
        name=body.name,
        role_arn=body.role_arn,
        max_ttl_seconds=body.max_ttl_seconds,
        description=body.description,
        owner=body.owner,
        actor=actor_of(principal),
    )
    return json_response(201, role_json(role))


@router.get("/v1/roles/{name}")
def get_role(name: RoleName, _: Admin, services: Services) -> dict[str, JsonValue]:
    role, templates = services.registry.get_role(name)
    return {**role_json(role), "session_policies": [template_json(t) for t in templates]}


@router.patch("/v1/roles/{name}")
async def patch_role(
    name: RoleName, request: Request, principal: Admin, services: Services
) -> JSONResponse:
    body = await read_json(request, RolePatch, max_bytes=MAX_JSON_BYTES)
    role = await run_in_threadpool(
        services.registry.update_role,
        name,
        actor=actor_of(principal),
        max_ttl_seconds=body.max_ttl_seconds,
        enabled=body.enabled,
        description=body.description,
        owner=body.owner,
    )
    return json_response(200, role_json(role))


@router.get("/v1/roles/{name}/session-policies")
def list_templates(name: RoleName, _: Admin, services: Services) -> dict[str, JsonValue]:
    _role, templates = services.registry.get_role(name)
    return {"session_policies": [template_json(t) for t in templates]}


@router.post("/v1/roles/{name}/session-policies")
async def add_template(
    name: RoleName, request: Request, principal: Admin, services: Services
) -> JSONResponse:
    body = await read_json(request, TemplateCreate, max_bytes=MAX_JSON_BYTES)
    template = await run_in_threadpool(
        services.registry.add_template,
        name,
        ref=body.ref,
        policy_document=body.policy_document,
        actor=actor_of(principal),
    )
    return json_response(201, template_json(template))


@router.post("/v1/revocations")
async def revoke(request: Request, principal: Admin, services: Services) -> JSONResponse:
    body = await read_json(request, RevocationRequest, max_bytes=MAX_JSON_BYTES)
    now = datetime.now(UTC)
    not_before = body.not_before or now
    # A future cut-off would also deny sessions minted after this call, until that moment.
    if not_before > now + NOT_BEFORE_FUTURE_SKEW:
        raise rejected(400, "VALIDATION_FAILED", "not_before must not be in the future")
    result = await run_in_threadpool(
        services.revocations.revoke_role,
        body.role,
        not_before=not_before,
        actor=principal.name,
        admin_principal_id=principal.id,
    )
    return json_response(
        201,
        {
            "revocation_id": str(result.revocation_id),
            "role": result.role_name,
            "not_before": result.not_before.astimezone(UTC).isoformat(),
            "applied": result.applied,
            "policy_name": result.policy_name,
            # Mechanism 3 OFF (default): the operator applies this document by runbook.
            "rendered_policy": result.rendered_policy,
        },
    )
