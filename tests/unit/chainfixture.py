"""In-memory writer for verifier tests — mirrors PostgresAuditSink without a database."""

import dataclasses
import json
from datetime import UTC, datetime, timedelta

from keystone.audit.canonical import canonicalize
from keystone.audit.chain import GENESIS_PREV_HASH, compute_event_hash
from keystone.audit.events import AuditEventInput, EventType, canonical_object
from keystone.audit.verify import ChainHead, StoredEvent
from keystone.db.ids import uuid7

T0 = datetime(2026, 9, 18, tzinfo=UTC)


def build_chain(n: int) -> tuple[list[StoredEvent], ChainHead]:
    events: list[StoredEvent] = []
    prev = GENESIS_PREV_HASH
    for seq in range(1, n + 1):
        event = AuditEventInput(
            event_type=EventType.DECISION_ALLOWED,
            occurred_at=T0 + timedelta(seconds=seq),
            actor=f"actor-{seq}",
            data={"n": seq},
        )
        event_id = uuid7()
        payload = canonicalize(canonical_object(seq, event_id, event))
        event_hash = compute_event_hash(prev, payload)
        events.append(
            StoredEvent(
                seq=seq,
                id=event_id,
                event_type=event.event_type.value,
                occurred_at=event.occurred_at,
                canonical_payload=payload,
                details=json.loads(payload),
                prev_hash=prev,
                event_hash=event_hash,
            )
        )
        prev = event_hash
    return events, ChainHead(seq=n, head_hash=prev)


def replace(event: StoredEvent, **changes: object) -> StoredEvent:
    return dataclasses.replace(event, **changes)  # type: ignore[arg-type]
