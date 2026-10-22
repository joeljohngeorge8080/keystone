"""Read side of the audit chain: snapshot head and ordered event ranges (Ch. 33, R7)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.engine import Connection

from keystone.audit.chain import GENESIS_PREV_HASH
from keystone.audit.verify import ChainHead, StoredEvent

_HEAD = text("SELECT seq, head_hash FROM audit_chain_head WHERE singleton = 1")
_RANGE = text(
    """
    SELECT seq, id, event_type, occurred_at, canonical_payload, details, prev_hash, event_hash
    FROM audit_events WHERE seq BETWEEN :lo AND :hi ORDER BY seq
    """
)
_HASH_AT = text("SELECT event_hash FROM audit_events WHERE seq = :seq")
_COLUMNS = "seq, id, event_type, occurred_at, canonical_payload, details, prev_hash, event_hash"
_PAGE = text(
    f"SELECT {_COLUMNS} FROM audit_events WHERE seq > :after "  # noqa: S608 — constant columns
    "AND (CAST(:event_type AS text) IS NULL OR event_type = :event_type) "
    "ORDER BY seq LIMIT :limit"
)
_FOR_DECISION = text(
    f"SELECT {_COLUMNS} FROM audit_events "  # noqa: S608 — constant columns
    "WHERE details -> 'data' ->> 'decision_id' = :decision_id AND occurred_at >= :since "
    "ORDER BY seq"
)
# Decision ids are UUIDv7 minted just before the decision is chained; looking back this far from
# the id's own timestamp lets PostgreSQL prune every older monthly partition.
_DECISION_LOOKBACK = timedelta(minutes=5)


def snapshot_head(connection: Connection) -> ChainHead:
    seq, head_hash = connection.execute(_HEAD).one()
    return ChainHead(seq=int(seq), head_hash=bytes(head_hash))


def prev_hash_before(connection: Connection, seq: int) -> bytes:
    if seq <= 1:
        return GENESIS_PREV_HASH
    row = connection.execute(_HASH_AT, {"seq": seq - 1}).one_or_none()
    if row is None:
        raise LookupError(f"no event at seq {seq - 1}; cannot anchor a range starting at {seq}")
    return bytes(row[0])


def load_events(connection: Connection, lo: int, hi: int) -> list[StoredEvent]:
    return _stored(connection.execute(_RANGE, {"lo": lo, "hi": hi}))


def page_events(
    connection: Connection, *, after_seq: int, limit: int, event_type: str | None = None
) -> list[StoredEvent]:
    """Keyset page in chain order: events with seq > after_seq, at most `limit`."""
    params = {"after": after_seq, "limit": limit, "event_type": event_type}
    return _stored(connection.execute(_PAGE, params))


def events_for_decision(connection: Connection, decision_id: uuid.UUID) -> list[StoredEvent]:
    """The decision and every event that cites it (issuance outcome, reconciler closure)."""
    since = datetime(1970, 1, 1, tzinfo=UTC)
    if decision_id.version == 7:
        minted = datetime.fromtimestamp((decision_id.int >> 80) / 1000, tz=UTC)
        since = minted - _DECISION_LOOKBACK
    rows = connection.execute(_FOR_DECISION, {"decision_id": str(decision_id), "since": since})
    return _stored(rows)


def _stored(rows: object) -> list[StoredEvent]:
    return [
        StoredEvent(
            seq=int(r.seq),
            id=r.id,
            event_type=r.event_type,
            occurred_at=r.occurred_at,
            canonical_payload=bytes(r.canonical_payload),
            details=r.details,
            prev_hash=bytes(r.prev_hash),
            event_hash=bytes(r.event_hash),
        )
        for r in rows  # type: ignore[attr-defined]
    ]
