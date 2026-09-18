"""Pure chain verifier — spec Ch. 33 + R1/R7. Hashes stored bytes only; never re-canonicalizes."""

from __future__ import annotations

import enum
import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from pydantic import JsonValue

from keystone.audit.chain import GENESIS_PREV_HASH, compute_event_hash
from keystone.audit.events import format_rfc3339


@dataclass(frozen=True, slots=True)
class StoredEvent:
    seq: int
    id: uuid.UUID
    event_type: str
    occurred_at: datetime
    canonical_payload: bytes
    details: JsonValue | None
    prev_hash: bytes
    event_hash: bytes


class FindingCode(enum.StrEnum):
    SEQ_GAP = "SEQ_GAP"
    CHAIN_BREAK = "CHAIN_BREAK"
    HASH_MISMATCH = "HASH_MISMATCH"
    CANONICAL_UNPARSEABLE = "CANONICAL_UNPARSEABLE"
    COLUMN_DIVERGENCE = "COLUMN_DIVERGENCE"
    DETAILS_DIVERGENCE = "DETAILS_DIVERGENCE"
    HEAD_MISMATCH = "HEAD_MISMATCH"


@dataclass(frozen=True, slots=True)
class Finding:
    code: FindingCode
    seq: int
    message: str


@dataclass(frozen=True, slots=True)
class ChainHead:
    seq: int
    head_hash: bytes


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    events_verified: int
    last_verified_seq: int | None
    finding: Finding | None


def _as_decimal(value: int | float) -> Decimal:
    return Decimal(repr(value)) if isinstance(value, float) else Decimal(value)


def json_equal(a: JsonValue, b: JsonValue) -> bool:
    """Structural equality where 1e+30 == 1000000000000000000000000000000 but 10**30+1 does not.

    PostgreSQL stores JSON numbers as exact numerics and prints them without exponents, so the
    `details` projection can decode to a different Python type than the canonical bytes while
    denoting the same number. Comparing as Decimal is exact for every value JCS can emit.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, int | float) and isinstance(b, int | float):
        return _as_decimal(a) == _as_decimal(b)
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b, strict=True))
    return type(a) is type(b) and a == b


def _check_event(event: StoredEvent, expected_seq: int, expected_prev: bytes) -> Finding | None:
    if event.seq != expected_seq:
        return Finding(FindingCode.SEQ_GAP, event.seq, f"expected seq {expected_seq}")
    if event.prev_hash != expected_prev:
        return Finding(FindingCode.CHAIN_BREAK, event.seq, "prev_hash != previous event_hash")
    if compute_event_hash(event.prev_hash, event.canonical_payload) != event.event_hash:
        return Finding(FindingCode.HASH_MISMATCH, event.seq, "stored event_hash does not recompute")
    try:
        canonical: JsonValue = json.loads(event.canonical_payload)
    except ValueError as exc:
        return Finding(FindingCode.CANONICAL_UNPARSEABLE, event.seq, str(exc))
    if not isinstance(canonical, dict):
        return Finding(FindingCode.CANONICAL_UNPARSEABLE, event.seq, "canonical is not an object")
    projected = {
        "seq": event.seq,
        "id": str(event.id),
        "event_type": event.event_type,
        "occurred_at": format_rfc3339(event.occurred_at),
    }
    for column, value in projected.items():
        if canonical.get(column) != value:
            return Finding(
                FindingCode.COLUMN_DIVERGENCE, event.seq, f"column {column} != canonical"
            )
    if event.details is not None and not json_equal(event.details, canonical):
        return Finding(FindingCode.DETAILS_DIVERGENCE, event.seq, "details != canonical_payload")
    return None


def verify_chain(
    events: Iterable[StoredEvent],
    *,
    expected_seq: int = 1,
    expected_prev_hash: bytes = GENESIS_PREV_HASH,
    expected_head: ChainHead | None = None,
) -> VerificationResult:
    """Verify the closed range starting at `expected_seq`; stops at the first divergence.

    `expected_head` is the snapshot head pinned before reading (R7) — when given, the last
    event must be exactly that head, so a deleted tail is reported as HEAD_MISMATCH.
    """
    count = 0
    last_seq: int | None = None
    verified_through = expected_seq - 1
    last_hash = expected_prev_hash
    for event in events:
        finding = _check_event(event, expected_seq, last_hash)
        if finding is not None:
            return VerificationResult(False, count, last_seq, finding)
        count += 1
        last_seq = event.seq
        verified_through = event.seq
        last_hash = event.event_hash
        expected_seq += 1
    if expected_head is not None and (
        verified_through != expected_head.seq or last_hash != expected_head.head_hash
    ):
        return VerificationResult(
            False,
            count,
            last_seq,
            Finding(
                FindingCode.HEAD_MISMATCH,
                verified_through,
                f"chain ends at seq {verified_through} but head claims seq {expected_head.seq}",
            ),
        )
    return VerificationResult(True, count, last_seq, None)
