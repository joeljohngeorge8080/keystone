"""Audited registry mutations for the admin plane (Ch. 22, FR-8): role and template changes are
committed together with their `admin_role_changed` event, in one transaction.

Role ARNs pass the connector's `validate_registration` before anything is written; session
policy documents must fit the STS inline-policy limit as PostgreSQL will store them.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from psycopg.errors import UniqueViolation
from pydantic import JsonValue
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import AuditSink
from keystone.broker.connectors.base import INLINE_POLICY_MAX_CHARS
from keystone.registry.models import SessionPolicyTemplate, TargetRole
from keystone.registry.repo import RegistryCode, RegistryError, RoleRegistry

RegistrationCheck = Callable[[str, str | None], None]  # CredentialConnector.validate_registration


class RegistryConflict(Exception):
    http_status = 409

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RegistryInvalid(Exception):
    http_status = 400

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class Actor:
    name: str
    admin_principal_id: uuid.UUID | None


def _is_unique_violation(exc: IntegrityError) -> bool:
    return isinstance(exc.orig, UniqueViolation)


def check_policy_document(document: dict[str, JsonValue]) -> None:
    statements = document.get("Statement")
    if not isinstance(statements, list) or not statements:
        raise RegistryInvalid("TEMPLATE_INVALID", "policy document needs a non-empty Statement")
    # json.dumps' default separators match PostgreSQL's jsonb text form, which the CHECK measures.
    if len(json.dumps(document)) > INLINE_POLICY_MAX_CHARS:
        raise RegistryInvalid(
            "TEMPLATE_INVALID", f"policy document exceeds {INLINE_POLICY_MAX_CHARS} characters"
        )


class RegistryAdmin:
    def __init__(
        self,
        engine: Engine,
        audit: AuditSink,
        validate_registration: RegistrationCheck,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._engine = engine
        self._audit = audit
        self._validate = validate_registration
        self._clock = clock

    # ---- reads ----

    def list_roles(self) -> list[TargetRole]:
        with self._engine.connect() as conn:
            return RoleRegistry(conn).list_roles()

    def get_role(self, name: str) -> tuple[TargetRole, list[SessionPolicyTemplate]]:
        with self._engine.connect() as conn:
            registry = RoleRegistry(conn)
            role = self._require(registry, name)
            return role, registry.list_templates(role.id)

    # ---- writes ----

    def create_role(
        self,
        *,
        name: str,
        role_arn: str,
        max_ttl_seconds: int,
        description: str,
        owner: str,
        actor: Actor,
    ) -> TargetRole:
        try:
            self._validate(role_arn, None)
        except ValueError as exc:
            raise RegistryInvalid("REGISTRY_ROLE_INVALID", str(exc)) from exc
        try:
            with self._engine.begin() as conn:
                role = RoleRegistry(conn).register_role(
                    name=name,
                    role_arn=role_arn,
                    max_ttl_seconds=max_ttl_seconds,
                    description=description,
                    owner=owner,
                )
                self._append(conn, actor, role.name, "role_created", {"role_arn": role_arn})
        except IntegrityError as exc:
            if _is_unique_violation(exc):
                raise RegistryConflict(
                    "REGISTRY_ROLE_EXISTS", "a role with that name or ARN already exists"
                ) from exc
            raise
        return role

    def update_role(
        self,
        name: str,
        *,
        actor: Actor,
        max_ttl_seconds: int | None = None,
        enabled: bool | None = None,
        description: str | None = None,
        owner: str | None = None,
    ) -> TargetRole:
        with self._engine.begin() as conn:
            registry = RoleRegistry(conn)
            before = self._require(registry, name)
            after = registry.update_role(
                name,
                max_ttl_seconds=max_ttl_seconds,
                enabled=enabled,
                description=description,
                owner=owner,
            )
            diff: dict[str, JsonValue] = {
                field: {"from": getattr(before, field), "to": getattr(after, field)}
                for field in ("max_ttl_seconds", "enabled", "description", "owner")
                if getattr(before, field) != getattr(after, field)
            }
            if diff:  # a no-op patch changes nothing and is not audited
                self._append(conn, actor, name, "role_updated", {"changes": diff})
        return after

    def add_template(
        self, role_name: str, *, ref: str, policy_document: dict[str, JsonValue], actor: Actor
    ) -> SessionPolicyTemplate:
        check_policy_document(policy_document)
        try:
            with self._engine.begin() as conn:
                registry = RoleRegistry(conn)
                role = self._require(registry, role_name)
                template = registry.add_template(
                    role_id=role.id, ref=ref, policy_document=policy_document
                )
                self._append(
                    conn,
                    actor,
                    role.name,
                    "template_added",
                    {"ref": ref, "policy_document": policy_document},
                )
        except IntegrityError as exc:
            if _is_unique_violation(exc):
                raise RegistryConflict(
                    "TEMPLATE_EXISTS", f"template {ref!r} already exists for {role_name!r}"
                ) from exc
            raise
        return template

    @staticmethod
    def _require(registry: RoleRegistry, name: str) -> TargetRole:
        role = registry.get_role(name)
        if role is None:
            raise RegistryError(RegistryCode.ROLE_UNKNOWN, f"role {name!r} not found")
        return role

    def _append(
        self,
        conn: Connection,
        actor: Actor,
        role_name: str,
        action: str,
        extra: dict[str, JsonValue],
    ) -> None:
        self._audit.append(
            conn,
            AuditEventInput(
                event_type=EventType.ADMIN_ROLE_CHANGED,
                occurred_at=self._clock(),
                actor=actor.name,
                admin_principal_id=actor.admin_principal_id,
                data={"role": role_name, "action": action, **extra},
            ),
        )
