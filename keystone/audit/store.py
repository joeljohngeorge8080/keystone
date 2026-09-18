"""Read side of the audit chain: snapshot head and ordered event ranges (Ch. 33, R7)."""

from __future__ import annotations

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
    rows = connection.execute(_RANGE, {"lo": lo, "hi": hi})
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
        for r in rows
    ]
