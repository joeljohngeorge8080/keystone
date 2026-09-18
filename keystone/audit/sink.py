"""AuditSink seam (Ch. 54) and its PostgreSQL implementation (Ch. 32/33, R1).

The caller owns the transaction: the event commits with its business effect or not at all.
"""

from __future__ import annotations

import json
from typing import Protocol

from sqlalchemy import text
from sqlalchemy.engine import Connection

from keystone.audit.canonical import canonicalize
from keystone.audit.chain import compute_event_hash
from keystone.audit.events import AuditEventInput, canonical_object
from keystone.audit.verify import StoredEvent
from keystone.db.ids import uuid7


class AuditSink(Protocol):
    def append(self, connection: Connection, event: AuditEventInput) -> StoredEvent: ...


class NotInTransactionError(RuntimeError):
    pass


_LOCK_HEAD = text("SELECT seq, head_hash FROM audit_chain_head WHERE singleton = 1 FOR UPDATE")
_INSERT_EVENT = text(
    """
    INSERT INTO audit_events (
        seq, id, event_type, issuance_id, admin_principal_id, input_hash, policy_digest,
        occurred_at, details, canonical_payload, prev_hash, event_hash
    ) VALUES (
        :seq, :id, :event_type, :issuance_id, :admin_principal_id, :input_hash, :policy_digest,
        :occurred_at, CAST(:details AS jsonb), :canonical_payload, :prev_hash, :event_hash
    )
    """
)
_ADVANCE_HEAD = text(
    "UPDATE audit_chain_head SET seq = :seq, head_hash = :head_hash "
    "WHERE singleton = 1 AND seq = :expected_seq"
)


class PostgresAuditSink:
    def append(self, connection: Connection, event: AuditEventInput) -> StoredEvent:
        if not connection.in_transaction():
            raise NotInTransactionError("audit append must run inside the caller's transaction")
        head_seq, head_hash = connection.execute(_LOCK_HEAD).one()
        prev_hash = bytes(head_hash)
        seq = int(head_seq) + 1
        event_id = uuid7()
        canonical = canonical_object(seq, event_id, event)
        payload = canonicalize(canonical)
        event_hash = compute_event_hash(prev_hash, payload)
        connection.execute(
            _INSERT_EVENT,
            {
                "seq": seq,
                "id": event_id,
                "event_type": event.event_type.value,
                "issuance_id": event.issuance_id,
                "admin_principal_id": event.admin_principal_id,
                "input_hash": event.input_hash,
                "policy_digest": event.policy_digest,
                "occurred_at": event.occurred_at,
                # details is projected from the canonical bytes so equality holds by construction
                "details": payload.decode("utf-8"),
                "canonical_payload": payload,
                "prev_hash": prev_hash,
                "event_hash": event_hash,
            },
        )
        advanced = connection.execute(
            _ADVANCE_HEAD, {"seq": seq, "head_hash": event_hash, "expected_seq": head_seq}
        )
        if advanced.rowcount != 1:
            raise RuntimeError(f"audit_chain_head advance affected {advanced.rowcount} rows")
        return StoredEvent(
            seq=seq,
            id=event_id,
            event_type=event.event_type.value,
            occurred_at=event.occurred_at,
            canonical_payload=payload,
            details=json.loads(payload),
            prev_hash=prev_hash,
            event_hash=event_hash,
        )
