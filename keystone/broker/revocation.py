"""Revocation (Ch. 26, F6 ordering, R9 append-only).

Mechanism 3 (role-wide session invalidation) is opt-in and OFF by default. Order is fixed:
`revocation_flagged` committed -> IAM deny policy applied -> read back and confirmed ->
`revocation_applied`. The chain never claims an enforcement that was not confirmed; the reverse
crash (IAM done, log missing) is backfilled by `reconcile_open()` by appending, never rewriting.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import JsonValue
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import AuditSink
from keystone.db.ids import uuid7
from keystone.registry.repo import RoleRegistry

POLICY_NAME_PREFIX = "keystone-revoke-before-"


def render_deny_policy(not_before: datetime) -> dict[str, Any]:
    """Deny everything for sessions issued before `not_before` (aws:TokenIssueTime)."""
    stamp = not_before.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "KeystoneRevokeOlderSessions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": stamp}},
            }
        ],
    }


def policy_name_for(not_before: datetime) -> str:
    return POLICY_NAME_PREFIX + not_before.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


class RoleDenyApplier(Protocol):
    def apply(self, role_arn: str, not_before: datetime) -> str: ...

    def confirm(self, role_arn: str, policy_name: str, not_before: datetime) -> bool: ...


class RevocationNotEnabled(Exception):
    """Mechanism 3 is off: the deny policy is rendered for the human runbook, not applied."""

    def __init__(self, policy_document: dict[str, Any]) -> None:
        super().__init__("iam:PutRolePolicy is not enabled for the broker (Ch. 26 default)")
        self.policy_document = policy_document


class RevocationUnconfirmed(Exception):
    """IAM did not read back the deny policy: revocation_applied is NOT written."""


def _role_name_from_arn(role_arn: str) -> str:
    return role_arn.rsplit("/", 1)[-1]


class IamDenyPolicyApplier:
    def __init__(self, client: Any, *, enabled: bool) -> None:
        self._client = client
        self._enabled = enabled

    def apply(self, role_arn: str, not_before: datetime) -> str:
        if not self._enabled:
            raise RevocationNotEnabled(render_deny_policy(not_before))
        name = policy_name_for(not_before)
        self._client.put_role_policy(
            RoleName=_role_name_from_arn(role_arn),
            PolicyName=name,
            PolicyDocument=json.dumps(render_deny_policy(not_before), separators=(",", ":")),
        )
        return name

    def confirm(self, role_arn: str, policy_name: str, not_before: datetime) -> bool:
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            response = self._client.get_role_policy(
                RoleName=_role_name_from_arn(role_arn), PolicyName=policy_name
            )
        except (ClientError, BotoCoreError):
            return False
        document = response.get("PolicyDocument")
        if isinstance(document, str):
            from urllib.parse import unquote

            document = json.loads(unquote(document))
        return bool(document == render_deny_policy(not_before))


@dataclass(frozen=True, slots=True)
class RevocationResult:
    revocation_id: uuid.UUID
    role_name: str
    not_before: datetime
    applied: bool
    policy_name: str | None
    rendered_policy: dict[str, Any] | None


_INSERT = text(
    "INSERT INTO revocations (id, target_role_id, not_before, mechanism, state, flagged_by) "
    "VALUES (:id, :role_id, :not_before, :mechanism, 'flagged', :flagged_by)"
)
_MARK_APPLIED = text(
    "UPDATE revocations SET state = 'applied', policy_name = :policy_name, applied_at = :at "
    "WHERE id = :id AND state = 'flagged'"
)
_OPEN = text(
    "SELECT r.id, r.not_before, r.flagged_by, t.name AS role_name, t.role_arn "
    "FROM revocations r JOIN target_roles t ON t.id = r.target_role_id "
    "WHERE r.state = 'flagged' AND r.mechanism = 'iam_deny_policy' ORDER BY r.flagged_at"
)


class RevocationService:
    def __init__(
        self,
        engine: Engine,
        audit: AuditSink,
        applier: RoleDenyApplier,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._engine = engine
        self._audit = audit
        self._applier = applier
        self._clock = clock

    def revoke_role(self, role_name: str, *, not_before: datetime, actor: str) -> RevocationResult:
        rendered = render_deny_policy(not_before)
        # T1: flag first. If we crash after this, the reconciler finds an open flag.
        with self._engine.begin() as conn:
            role = RoleRegistry(conn).require_enabled_role(role_name)
            revocation_id = uuid7()
            mechanism = "iam_deny_policy"
            try:
                self._applier.confirm  # noqa: B018 — probe presence; enabled-ness is decided by apply()
            except AttributeError:  # pragma: no cover
                mechanism = "runbook"
            conn.execute(
                _INSERT,
                {
                    "id": revocation_id,
                    "role_id": role.id,
                    "not_before": not_before,
                    "mechanism": mechanism,
                    "flagged_by": actor,
                },
            )
            self._append(
                conn,
                EventType.REVOCATION_FLAGGED,
                actor,
                role.name,
                not_before,
                {"revocation_id": str(revocation_id)},
            )

        # Apply (mechanism 3) — outside any DB transaction.
        try:
            policy_name = self._applier.apply(role.role_arn, not_before)
        except RevocationNotEnabled as exc:
            with self._engine.begin() as conn:
                conn.execute(
                    text("UPDATE revocations SET mechanism = 'runbook' WHERE id = :id"),
                    {"id": revocation_id},
                )
            return RevocationResult(
                revocation_id, role.name, not_before, False, None, exc.policy_document
            )

        if not self._applier.confirm(role.role_arn, policy_name, not_before):
            raise RevocationUnconfirmed(f"deny policy {policy_name} not read back on {role.name}")

        # T2: only after confirmation does the chain claim enforcement.
        self._mark_applied(revocation_id, role.name, not_before, policy_name, actor)
        return RevocationResult(revocation_id, role.name, not_before, True, policy_name, rendered)

    def reconcile_open(self) -> int:
        """F6 reverse-crash backfill: IAM has the deny policy, the log lacks revocation_applied."""
        with self._engine.connect() as conn:
            open_rows = list(conn.execute(_OPEN))
        backfilled = 0
        for row in open_rows:
            policy_name = policy_name_for(row.not_before)
            if self._applier.confirm(row.role_arn, policy_name, row.not_before):
                self._mark_applied(
                    row.id, row.role_name, row.not_before, policy_name, "keystone-reconciler"
                )
                backfilled += 1
        return backfilled

    def _mark_applied(
        self,
        revocation_id: uuid.UUID,
        role_name: str,
        not_before: datetime,
        policy_name: str,
        actor: str,
    ) -> None:
        with self._engine.begin() as conn:
            updated = conn.execute(
                _MARK_APPLIED,
                {"policy_name": policy_name, "at": self._clock(), "id": revocation_id},
            ).rowcount
            if updated != 1:
                return  # already applied (idempotent)
            self._append(
                conn,
                EventType.REVOCATION_APPLIED,
                actor,
                role_name,
                not_before,
                {
                    "revocation_id": str(revocation_id),
                    "policy_name": policy_name,
                    "confirmed": True,
                },
            )

    def _append(
        self,
        conn: Connection,
        event_type: EventType,
        actor: str,
        role_name: str,
        not_before: datetime,
        extra: dict[str, JsonValue],
    ) -> None:
        self._audit.append(
            conn,
            AuditEventInput(
                event_type=event_type,
                occurred_at=self._clock(),
                actor=actor,
                data={
                    "role": role_name,
                    "not_before": not_before.astimezone(UTC).isoformat(),
                    **extra,
                },
            ),
        )
