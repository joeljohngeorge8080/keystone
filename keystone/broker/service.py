"""IssuanceService — FR-6 brokering with audit-before-mint ordering (Ch. 22-27, AMB-3/4).

Transaction shape:
  T1  registry lookup (DB half of the double allowlist) → post-decision validation → TTL clamp →
      issuances row committed in AUTHORIZED. A crash after T1 leaves a row the startup
      reconciler resolves (R6).
  --  connector.mint outside any transaction (never hold a DB lock across an AWS call).
  T2  audit event + state transition in ONE transaction (credential_issued → ISSUED,
      sts_indeterminate → INDETERMINATE, credential_issue_failed → FAILED).
The caller marks DELIVERED after the single-shot response is written.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator
from sqlalchemy.engine import Connection, Engine

from keystone.audit.events import AuditEventInput, EventType, assert_no_forbidden_keys
from keystone.audit.sink import AuditSink
from keystone.broker.connectors.base import (
    ConnectorError,
    CredentialConnector,
    IndeterminateError,
    IssuedCredential,
    MintRequest,
)
from keystone.broker.issuance import Issuance, IssuanceRepository, IssuanceState
from keystone.broker.ttl import TtlExceedsAllowed, clamp_ttl
from keystone.registry.models import NAME_PATTERN
from keystone.registry.repo import RegistryError, RoleRegistry


class AuthorizedDecision(BaseModel):
    """The allow decision as validated by the authz stage (Ch. 19 decision object)."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    decision_id: uuid.UUID
    decision_audit_seq: int = Field(ge=1)
    grant: str = Field(pattern=NAME_PATTERN)
    ttl_cap_seconds: int = Field(ge=900, le=3600)
    session_policy_ref: str = Field(pattern=NAME_PATTERN)
    rule_path: str = Field(min_length=1, max_length=256)
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_pin_id: uuid.UUID
    deny_on_ttl_excess: bool = False


class IdentityContext(BaseModel):
    """Verified claims the broker needs; passed verbatim, never defaulted (R2 input rule)."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    jti_hash: bytes = Field(min_length=32, max_length=32)
    actor: str = Field(min_length=1, max_length=256)
    repository: str = Field(min_length=1, max_length=256)
    repository_id: str = Field(pattern=r"^[0-9]{1,20}$")
    run_id: str = Field(pattern=r"^[0-9]{1,20}$")
    ref: str = Field(min_length=1, max_length=256)
    workflow_ref: str = Field(min_length=1, max_length=512)
    claims: dict[str, JsonValue]

    @field_validator("claims")
    @classmethod
    def _no_secret_material(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        # identity_claims is persisted as JSONB (Ch. 36); a raw token must never ride along.
        assert_no_forbidden_keys(value)
        return value


class PolicyRegistryDivergence(Exception):
    """Policy and registry disagree (Ch. 19 post-decision validation) — 500, audited, alarmed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class TtlDenied(Exception):
    code = "TTL_EXCEEDS_ALLOWED"


@dataclass(frozen=True, slots=True)
class IssuanceResult:
    issuance: Issuance
    credential: IssuedCredential
    granted_ttl_seconds: int
    ttl_clamped: bool
    ttl_raised: bool
    audit_seq: int


def session_name_for(identity: IdentityContext, decision_audit_seq: int) -> str:
    return f"ks-{identity.repository_id}-{identity.run_id}-{decision_audit_seq}"


class IssuanceService:
    def __init__(self, engine: Engine, audit: AuditSink, connector: CredentialConnector) -> None:
        self._engine = engine
        self._audit = audit
        self._connector = connector

    def issue(
        self,
        decision: AuthorizedDecision,
        identity: IdentityContext,
        requested_ttl_seconds: int | None,
    ) -> IssuanceResult:
        issuance, request, ttl_clamped, ttl_raised = self._authorize(
            decision, identity, requested_ttl_seconds
        )
        try:
            credential = self._connector.mint(request)
        except IndeterminateError as exc:
            self._record_failure(
                issuance,
                decision,
                identity,
                EventType.STS_INDETERMINATE,
                IssuanceState.INDETERMINATE,
                exc,
            )
            raise
        except ConnectorError as exc:
            self._record_failure(
                issuance,
                decision,
                identity,
                EventType.CREDENTIAL_ISSUE_FAILED,
                IssuanceState.FAILED,
                exc,
            )
            raise
        audit_seq = self._record_issued(
            issuance, decision, identity, credential, ttl_clamped, ttl_raised
        )
        issued = issuance.model_copy(
            update={
                "state": IssuanceState.ISSUED,
                "access_key_prefix": credential.access_key_prefix,
                "expires_at": credential.expiration,
            }
        )
        return IssuanceResult(
            issuance=issued,
            credential=credential,
            granted_ttl_seconds=issuance.granted_ttl_seconds,
            ttl_clamped=ttl_clamped,
            ttl_raised=ttl_raised,
            audit_seq=audit_seq,
        )

    def mark_delivered(self, issuance_id: uuid.UUID) -> None:
        with self._engine.begin() as conn:
            IssuanceRepository(conn).transition(
                issuance_id, IssuanceState.ISSUED, IssuanceState.DELIVERED
            )

    # ---- T1 ----

    def _authorize(
        self,
        decision: AuthorizedDecision,
        identity: IdentityContext,
        requested_ttl_seconds: int | None,
    ) -> tuple[Issuance, MintRequest, bool, bool]:
        try:
            return self._authorize_txn(decision, identity, requested_ttl_seconds)
        except (RegistryError, PolicyRegistryDivergence, TtlDenied) as exc:
            # The failing transaction has rolled back; the refusal is audited in its own one.
            reason = exc.code.value if isinstance(exc, RegistryError) else exc.code
            with self._engine.begin() as conn:
                self._audit_unissued(conn, decision, identity, reason)
            raise

    def _authorize_txn(
        self,
        decision: AuthorizedDecision,
        identity: IdentityContext,
        requested_ttl_seconds: int | None,
    ) -> tuple[Issuance, MintRequest, bool, bool]:
        with self._engine.begin() as conn:
            registry = RoleRegistry(conn)
            role = registry.require_enabled_role(decision.grant)
            template = registry.require_template(role.id, decision.session_policy_ref)
            if decision.ttl_cap_seconds > role.max_ttl_seconds:
                raise PolicyRegistryDivergence(
                    "POLICY_REGISTRY_DIVERGENCE",
                    f"policy ttl_cap {decision.ttl_cap_seconds} exceeds registry max "
                    f"{role.max_ttl_seconds} for {role.name}",
                )
            try:
                ttl = clamp_ttl(
                    requested_ttl_seconds,
                    policy_cap=decision.ttl_cap_seconds,
                    registry_max=role.max_ttl_seconds,
                    deny_on_excess=decision.deny_on_ttl_excess,
                )
            except TtlExceedsAllowed as exc:
                raise TtlDenied(str(exc)) from exc
            session_name = session_name_for(identity, decision.decision_audit_seq)
            issuance = IssuanceRepository(conn).create_authorized(
                jti_hash=identity.jti_hash,
                target_role_id=role.id,
                policy_pin_id=decision.policy_pin_id,
                grant_name=decision.grant,
                session_name=session_name,
                session_policy_ref=template.ref,
                granted_ttl_seconds=ttl.effective,
                identity_claims=identity.claims,
            )
            request = MintRequest(
                role_arn=role.role_arn,
                session_name=session_name,
                duration_seconds=ttl.effective,
                session_policy=template.policy_document,
                tags={
                    "keystone:decision_id": str(decision.decision_id),
                    "keystone:repository": identity.repository,
                    "keystone:ref": identity.ref,
                    "keystone:workflow_ref": identity.workflow_ref,
                    "keystone:actor": identity.actor,
                },
                external_id=role.external_id,
            )
        return issuance, request, ttl.clamped, ttl.raised

    # ---- T2 ----

    def _record_issued(
        self,
        issuance: Issuance,
        decision: AuthorizedDecision,
        identity: IdentityContext,
        credential: IssuedCredential,
        ttl_clamped: bool,
        ttl_raised: bool,
    ) -> int:
        with self._engine.begin() as conn:
            IssuanceRepository(conn).transition(
                issuance.id,
                IssuanceState.AUTHORIZED,
                IssuanceState.ISSUED,
                access_key_prefix=credential.access_key_prefix,
                expires_at=credential.expiration,
            )
            stored = self._audit.append(
                conn,
                AuditEventInput(
                    event_type=EventType.CREDENTIAL_ISSUED,
                    occurred_at=datetime.now(UTC),
                    actor=identity.actor,
                    issuance_id=issuance.id,
                    policy_digest=decision.policy_digest,
                    data={
                        "decision_id": str(decision.decision_id),
                        "grant": decision.grant,
                        "session_name": issuance.session_name,
                        "access_key_prefix": credential.access_key_prefix,
                        "granted_ttl_seconds": issuance.granted_ttl_seconds,
                        "ttl_clamped": ttl_clamped,
                        "ttl_raised": ttl_raised,
                        "expires_at": credential.expiration.astimezone(UTC).isoformat(),
                    },
                ),
            )
        return stored.seq

    def _record_failure(
        self,
        issuance: Issuance,
        decision: AuthorizedDecision,
        identity: IdentityContext,
        event_type: EventType,
        to_state: IssuanceState,
        error: ConnectorError,
    ) -> None:
        with self._engine.begin() as conn:
            IssuanceRepository(conn).transition(issuance.id, IssuanceState.AUTHORIZED, to_state)
            self._audit.append(
                conn,
                AuditEventInput(
                    event_type=event_type,
                    occurred_at=datetime.now(UTC),
                    actor=identity.actor,
                    issuance_id=issuance.id,
                    policy_digest=decision.policy_digest,
                    data={
                        "decision_id": str(decision.decision_id),
                        "grant": decision.grant,
                        "session_name": issuance.session_name,
                        "error_class": type(error).__name__,
                        "http_status": error.http_status,
                    },
                ),
            )

    def _audit_unissued(
        self,
        conn: Connection,
        decision: AuthorizedDecision,
        identity: IdentityContext,
        reason: str,
    ) -> None:
        self._audit.append(
            conn,
            AuditEventInput(
                event_type=EventType.CREDENTIAL_ISSUE_FAILED,
                occurred_at=datetime.now(UTC),
                actor=identity.actor,
                policy_digest=decision.policy_digest,
                data={
                    "decision_id": str(decision.decision_id),
                    "grant": decision.grant,
                    "reason": reason,
                },
            ),
        )
