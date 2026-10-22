"""Read-only audit and issuance routes (Ch. 32/33/40/42).

Events are rendered from their `canonical_payload` bytes, never from the `details` projection,
so what an operator sees is exactly what was hashed (R1). Lists use keyset pagination.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import JsonValue

from keystone.admin.deps import Admin, Services
from keystone.api.errors import rejected
from keystone.audit.events import EventType
from keystone.audit.store import (
    events_for_decision,
    load_events,
    page_events,
    prev_hash_before,
    snapshot_head,
)
from keystone.audit.verify import StoredEvent, verify_chain
from keystone.broker.issuance import Issuance, IssuanceRepository, IssuanceState

MAX_PAGE = 500
MAX_VERIFY_SPAN = 100_000  # events per call; larger ranges are walked with from_seq

router = APIRouter()


def event_json(event: StoredEvent) -> dict[str, JsonValue]:
    rendered: JsonValue = json.loads(event.canonical_payload)
    return {
        "seq": event.seq,
        "event_type": event.event_type,
        "event": rendered,
        "prev_hash": event.prev_hash.hex(),
        "event_hash": event.event_hash.hex(),
    }


def issuance_json(issuance: Issuance) -> dict[str, JsonValue]:
    claims = issuance.identity_claims
    return {
        "id": str(issuance.id),
        "state": issuance.state.value,
        "grant": issuance.grant_name,
        "session_name": issuance.session_name,
        "session_policy_ref": issuance.session_policy_ref,
        "access_key_prefix": issuance.access_key_prefix,
        "granted_ttl_seconds": issuance.granted_ttl_seconds,
        "expires_at": issuance.expires_at.astimezone(UTC).isoformat()
        if issuance.expires_at
        else None,
        "created_at": issuance.created_at.astimezone(UTC).isoformat(),
        "policy_pin_id": str(issuance.policy_pin_id),
        "repository": claims.get("repository"),
        "ref": claims.get("ref"),
        "actor": claims.get("actor"),
        "run_id": claims.get("run_id"),
    }


@router.get("/v1/decisions/{decision_id}")
def get_decision(decision_id: uuid.UUID, _: Admin, services: Services) -> dict[str, JsonValue]:
    with services.engine.connect() as conn:
        events = events_for_decision(conn, decision_id)
    if not events:
        raise rejected(404, "DECISION_NOT_FOUND", "no decision with that id")
    return {"decision_id": str(decision_id), "events": [event_json(e) for e in events]}


@router.get("/v1/audit/events")
def list_events(
    _: Admin,
    services: Services,
    after_seq: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 100,
    event_type: EventType | None = None,
) -> dict[str, JsonValue]:
    with services.engine.connect() as conn:
        events = page_events(
            conn,
            after_seq=after_seq,
            limit=limit,
            event_type=event_type.value if event_type else None,
        )
    return {
        "events": [event_json(e) for e in events],
        "next_after_seq": events[-1].seq if len(events) == limit else None,
    }


@router.get("/v1/audit/verify")
def verify(
    _: Admin,
    services: Services,
    from_seq: Annotated[int, Query(ge=1)] = 1,
    to_seq: Annotated[int | None, Query(ge=1)] = None,
) -> dict[str, JsonValue]:
    with services.engine.connect() as conn:
        head = snapshot_head(conn)  # pinned before reading (R7)
        if from_seq > head.seq + 1:
            raise rejected(400, "VALIDATION_FAILED", "from_seq is beyond the chain head")
        hi = min(head.seq, to_seq or head.seq, from_seq + MAX_VERIFY_SPAN - 1)
        prev = prev_hash_before(conn, from_seq)
        events = load_events(conn, from_seq, hi)
    result = verify_chain(
        events,
        expected_seq=from_seq,
        expected_prev_hash=prev,
        expected_head=head if hi == head.seq else None,
    )
    finding = result.finding
    return {
        "ok": result.ok,
        "events_verified": result.events_verified,
        "last_verified_seq": result.last_verified_seq,
        "head_seq": head.seq,
        "complete": hi == head.seq,
        "finding": None
        if finding is None
        else {"code": finding.code.value, "seq": finding.seq, "message": finding.message},
    }


@router.get("/v1/issuances")
def list_issuances(
    _: Admin,
    services: Services,
    before: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 100,
    state: IssuanceState | None = None,
) -> dict[str, JsonValue]:
    with services.engine.connect() as conn:
        rows = IssuanceRepository(conn).page(before=before, limit=limit, state=state)
    return {
        "issuances": [issuance_json(i) for i in rows],
        "next_before": str(rows[-1].id) if len(rows) == limit else None,
    }
