"""Authorization stage (Ch. 19, F3, F7, R5): one decision per request, audited before it is used.

Sequence: build input (claims verbatim, no fabricated defaults) -> evaluate -> validate shape ->
compare OPA's loaded digest with the committed DB pin (503 POLICY_PIN_DIVERGENCE on mismatch) ->
append decision_allowed / decision_denied to the chain -> return. The broker never mints on a
decision that is not already durable in the audit log (audit-before-mint).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import JsonValue
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import AuditSink
from keystone.authz.evaluator import INPUT_SCHEMA_VERSION, Decision, PolicyEvaluator, PolicyInput
from keystone.broker.service import AuthorizedDecision
from keystone.identity.oidc import VerifiedIdentity


class PolicyPinDivergence(Exception):
    """OPA's loaded bundle is not the committed pin: transient, fail closed (R5)."""

    http_status = 503
    code = "POLICY_PIN_DIVERGENCE"


class NoActivePin(Exception):
    """No committed pin exists: nothing may be authorized (fail closed)."""

    http_status = 503
    code = "POLICY_PIN_MISSING"


@dataclass(frozen=True, slots=True)
class ActivePin:
    id: uuid.UUID
    bundle_digest: str
    bundle_sequence: int


@dataclass(frozen=True, slots=True)
class Denied:
    decision_id: uuid.UUID
    audit_seq: int
    reasons: tuple[str, ...]
    rule_path: str | None
    policy_digest: str


_ACTIVE_PIN = text(
    "SELECT id, bundle_digest, bundle_sequence FROM policy_pins "
    "WHERE active ORDER BY pinned_at DESC LIMIT 1"
)


def active_pin(connection: Connection) -> ActivePin | None:
    row = connection.execute(_ACTIVE_PIN).one_or_none()
    if row is None:
        return None
    return ActivePin(
        id=row.id, bundle_digest=row.bundle_digest, bundle_sequence=int(row.bundle_sequence)
    )


def build_policy_input(
    identity: VerifiedIdentity,
    *,
    grant: str,
    requested_ttl_seconds: int | None,
    source_ip: str,
    received_at: datetime,
    keystone_version: str,
    policy_digest: str,
) -> PolicyInput:
    request: dict[str, JsonValue] = {
        "grant": grant,
        "requested_ttl_seconds": requested_ttl_seconds,
        "source_ip": source_ip,
        "received_at": received_at.astimezone(UTC).isoformat(),
    }
    return PolicyInput(
        schema=INPUT_SCHEMA_VERSION,
        identity=dict(identity.claims),  # verbatim and complete: absent stays absent (R2)
        request=request,
        context={"keystone_version": keystone_version, "policy_version": policy_digest},
    )


class AuthorizationService:
    def __init__(
        self,
        engine: Engine,
        audit: AuditSink,
        evaluator: PolicyEvaluator,
        *,
        keystone_version: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._engine = engine
        self._audit = audit
        self._evaluator = evaluator
        self._version = keystone_version
        self._clock = clock

    def authorize(
        self,
        identity: VerifiedIdentity,
        *,
        grant: str,
        requested_ttl_seconds: int | None,
        source_ip: str,
        decision_id: uuid.UUID,
    ) -> AuthorizedDecision | Denied:
        with self._engine.connect() as conn:
            pin = active_pin(conn)
        if pin is None:
            raise NoActivePin("no active policy pin")
        policy_input = build_policy_input(
            identity,
            grant=grant,
            requested_ttl_seconds=requested_ttl_seconds,
            source_ip=source_ip,
            received_at=identity.verified_at,
            keystone_version=self._version,
            policy_digest=pin.bundle_digest,
        )
        decision = self._evaluator.evaluate(policy_input)
        if decision.loaded_bundle_digest != pin.bundle_digest:
            self._audit_divergence(identity, decision, pin, policy_input, decision_id)
            raise PolicyPinDivergence(
                f"OPA has {decision.loaded_bundle_digest}, pin is {pin.bundle_digest}"
            )
        seq = self._audit_decision(identity, decision, pin, policy_input, decision_id)
        if not decision.allow:
            return Denied(
                decision_id=decision_id,
                audit_seq=seq,
                reasons=tuple(decision.deny_reasons),
                rule_path=decision.rule_path,
                policy_digest=pin.bundle_digest,
            )
        assert decision.grant is not None and decision.session_policy_ref is not None
        assert decision.rule_path is not None
        return AuthorizedDecision(
            decision_id=decision_id,
            decision_audit_seq=seq,
            grant=decision.grant.replace("_", "-"),
            ttl_cap_seconds=decision.ttl_cap_seconds,
            session_policy_ref=decision.session_policy_ref,
            rule_path=decision.rule_path,
            policy_digest=pin.bundle_digest,
            policy_pin_id=pin.id,
        )

    def _audit_decision(
        self,
        identity: VerifiedIdentity,
        decision: Decision,
        pin: ActivePin,
        policy_input: PolicyInput,
        decision_id: uuid.UUID,
    ) -> int:
        data: dict[str, JsonValue] = {
            "decision_id": str(decision_id),
            "grant": policy_input.request["grant"],
            "rule_path": decision.rule_path,
            "deny_reasons": list(decision.deny_reasons),
            "ttl_cap_seconds": decision.ttl_cap_seconds,
            "session_policy_ref": decision.session_policy_ref,
            "obligations": decision.obligations,
            "policy_pin_id": str(pin.id),
            "bundle_sequence": pin.bundle_sequence,
            "sub": identity.sub,
            "repository": identity.repository,
            "ref": identity.ref,
        }
        event = AuditEventInput(
            event_type=EventType.DECISION_ALLOWED if decision.allow else EventType.DECISION_DENIED,
            occurred_at=self._clock(),
            actor=identity.sub,
            input_hash=policy_input.input_hash(),
            policy_digest=decision.loaded_bundle_digest,
            data=data,
        )
        with self._engine.begin() as conn:
            return self._audit.append(conn, event).seq

    def _audit_divergence(
        self,
        identity: VerifiedIdentity,
        decision: Decision,
        pin: ActivePin,
        policy_input: PolicyInput,
        decision_id: uuid.UUID,
    ) -> None:
        event = AuditEventInput(
            event_type=EventType.DECISION_DENIED,
            occurred_at=self._clock(),
            actor=identity.sub,
            input_hash=policy_input.input_hash(),
            policy_digest=decision.loaded_bundle_digest,
            data={
                "decision_id": str(decision_id),
                "grant": policy_input.request["grant"],
                "deny_reasons": ["POLICY_PIN_DIVERGENCE"],
                "pinned_digest": pin.bundle_digest,
                "loaded_digest": decision.loaded_bundle_digest,
            },
        )
        with self._engine.begin() as conn:
            self._audit.append(conn, event)
