"""Registry repository — reads and admin writes over target_roles / session_policy_templates."""

from __future__ import annotations

import enum
import json
import uuid

from pydantic import JsonValue
from sqlalchemy import text
from sqlalchemy.engine import Connection

from keystone.db.ids import uuid7
from keystone.registry.models import SessionPolicyTemplate, TargetRole


class RegistryCode(enum.StrEnum):
    ROLE_UNKNOWN = "REGISTRY_ROLE_UNKNOWN"
    ROLE_DISABLED = "REGISTRY_ROLE_DISABLED"
    TEMPLATE_UNKNOWN = "TEMPLATE_UNKNOWN"
    TEMPLATE_DISABLED = "TEMPLATE_DISABLED"


class RegistryError(Exception):
    def __init__(self, code: RegistryCode, message: str) -> None:
        super().__init__(message)
        self.code = code


_ROLE_COLUMNS = "id, name, role_arn, max_ttl_seconds, external_id, enabled, description, owner"
_GET_ROLE = text(f"SELECT {_ROLE_COLUMNS} FROM target_roles WHERE name = :name")  # noqa: S608
_INSERT_ROLE = text(
    "INSERT INTO target_roles (id, name, role_arn, max_ttl_seconds, external_id, enabled, "
    "description, owner) VALUES (:id, :name, :role_arn, :max_ttl_seconds, :external_id, "
    ":enabled, :description, :owner)"
)
_SET_ROLE_ENABLED = text(
    "UPDATE target_roles SET enabled = :enabled, updated_at = now() WHERE name = :name"
)
_LIST_ROLES = text(f"SELECT {_ROLE_COLUMNS} FROM target_roles ORDER BY name")  # noqa: S608
# COALESCE keeps every column the patch leaves as NULL; no SQL is assembled from input.
_UPDATE_ROLE = text(
    "UPDATE target_roles SET "  # noqa: S608 — constant column list, bound values only
    "max_ttl_seconds = COALESCE(:max_ttl_seconds, max_ttl_seconds), "
    "enabled = COALESCE(:enabled, enabled), "
    "description = COALESCE(:description, description), "
    "owner = COALESCE(:owner, owner), updated_at = now() "
    f"WHERE name = :name RETURNING {_ROLE_COLUMNS}"
)
_LIST_TEMPLATES = text(
    "SELECT id, target_role_id, ref, policy_document, enabled FROM session_policy_templates "
    "WHERE target_role_id = :role_id ORDER BY ref"
)
_GET_TEMPLATE = text(
    "SELECT id, target_role_id, ref, policy_document, enabled FROM session_policy_templates "
    "WHERE target_role_id = :role_id AND ref = :ref"
)
_INSERT_TEMPLATE = text(
    "INSERT INTO session_policy_templates (id, target_role_id, ref, policy_document, enabled) "
    "VALUES (:id, :role_id, :ref, CAST(:policy AS jsonb), :enabled)"
)


class RoleRegistry:
    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def get_role(self, name: str) -> TargetRole | None:
        row = self._conn.execute(_GET_ROLE, {"name": name}).one_or_none()
        return None if row is None else TargetRole(**row._mapping)

    def require_enabled_role(self, name: str) -> TargetRole:
        role = self.get_role(name)
        if role is None:
            raise RegistryError(RegistryCode.ROLE_UNKNOWN, f"grant {name!r} has no registered role")
        if not role.enabled:
            raise RegistryError(RegistryCode.ROLE_DISABLED, f"role {name!r} is disabled")
        return role

    def get_template(self, role_id: uuid.UUID, ref: str) -> SessionPolicyTemplate | None:
        row = self._conn.execute(_GET_TEMPLATE, {"role_id": role_id, "ref": ref}).one_or_none()
        return None if row is None else SessionPolicyTemplate(**row._mapping)

    def require_template(self, role_id: uuid.UUID, ref: str) -> SessionPolicyTemplate:
        template = self.get_template(role_id, ref)
        if template is None:
            raise RegistryError(RegistryCode.TEMPLATE_UNKNOWN, f"template {ref!r} not approved")
        if not template.enabled:
            raise RegistryError(RegistryCode.TEMPLATE_DISABLED, f"template {ref!r} is disabled")
        return template

    # ---- admin-plane writes (audited by the caller) ----

    def register_role(
        self,
        *,
        name: str,
        role_arn: str,
        max_ttl_seconds: int,
        external_id: str | None = None,
        enabled: bool = True,
        description: str = "",
        owner: str = "",
    ) -> TargetRole:
        role = TargetRole(
            id=uuid7(),
            name=name,
            role_arn=role_arn,
            max_ttl_seconds=max_ttl_seconds,
            external_id=external_id,
            enabled=enabled,
            description=description,
            owner=owner,
        )
        self._conn.execute(_INSERT_ROLE, role.model_dump())
        return role

    def list_roles(self) -> list[TargetRole]:
        return [TargetRole(**row._mapping) for row in self._conn.execute(_LIST_ROLES)]

    def update_role(
        self,
        name: str,
        *,
        max_ttl_seconds: int | None = None,
        enabled: bool | None = None,
        description: str | None = None,
        owner: str | None = None,
    ) -> TargetRole:
        """Patch mutable fields. `role_arn` is deliberately not patchable: re-pointing an
        approved grant at a different AWS role must be a new, separately reviewed role."""
        row = self._conn.execute(
            _UPDATE_ROLE,
            {
                "name": name,
                "max_ttl_seconds": max_ttl_seconds,
                "enabled": enabled,
                "description": description,
                "owner": owner,
            },
        ).one_or_none()
        if row is None:
            raise RegistryError(RegistryCode.ROLE_UNKNOWN, f"role {name!r} not found")
        return TargetRole(**row._mapping)

    def list_templates(self, role_id: uuid.UUID) -> list[SessionPolicyTemplate]:
        rows = self._conn.execute(_LIST_TEMPLATES, {"role_id": role_id})
        return [SessionPolicyTemplate(**row._mapping) for row in rows]

    def set_role_enabled(self, name: str, enabled: bool) -> None:
        if self._conn.execute(_SET_ROLE_ENABLED, {"name": name, "enabled": enabled}).rowcount != 1:
            raise RegistryError(RegistryCode.ROLE_UNKNOWN, f"role {name!r} not found")

    def add_template(
        self,
        *,
        role_id: uuid.UUID,
        ref: str,
        policy_document: dict[str, JsonValue],
        enabled: bool = True,
    ) -> SessionPolicyTemplate:
        template = SessionPolicyTemplate(
            id=uuid7(),
            target_role_id=role_id,
            ref=ref,
            policy_document=policy_document,
            enabled=enabled,
        )
        self._conn.execute(
            _INSERT_TEMPLATE,
            {
                "id": template.id,
                "role_id": role_id,
                "ref": ref,
                "policy": json.dumps(policy_document, separators=(",", ":")),
                "enabled": enabled,
            },
        )
        return template
