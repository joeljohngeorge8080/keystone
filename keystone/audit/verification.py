"""Scheduled chain verification (F9 / R7): snapshot head, closed range, pages on divergence."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from keystone.audit.anchor import (
    AnchorRecord,
    anchor_before,
    anchors_in_range,
    verify_anchor_signature,
)
from keystone.audit.chain import GENESIS_PREV_HASH
from keystone.audit.store import load_events, snapshot_head
from keystone.audit.verify import ChainHead, Finding, FindingCode, verify_chain

_STATE = text(
    "SELECT last_verified_seq, last_verified_hash FROM audit_verification_state "
    "WHERE singleton = 1 FOR UPDATE"
)
_ADVANCE = text(
    "UPDATE audit_verification_state SET last_verified_seq = :seq, last_verified_hash = :hash, "
    "verified_at = :at WHERE singleton = 1"
)


class ChainDivergence(Exception):
    """Raised (and meant to page) when the closed range does not verify."""

    def __init__(self, finding: Finding) -> None:
        super().__init__(finding.code + f" at seq {finding.seq}: {finding.message}")
        self.finding = finding


@dataclass(frozen=True, slots=True)
class VerificationPass:
    from_seq: int
    to_seq: int
    events_verified: int
    anchors_verified: int


class ChainVerificationTask:
    def __init__(
        self,
        engine: Engine,
        anchor_public_key: Ed25519PublicKey,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        max_events_per_pass: int = 50_000,
    ) -> None:
        self._engine = engine
        self._public_key = anchor_public_key
        self._clock = clock
        self._max = max_events_per_pass

    def run_once(self) -> VerificationPass:
        with self._engine.begin() as conn:
            last_seq, last_hash = conn.execute(_STATE).one()
            last_seq = int(last_seq)
            last_hash = bytes(last_hash) if last_seq else GENESIS_PREV_HASH
            head = snapshot_head(conn)  # pinned once; events appended after this are next pass's
            to_seq = min(head.seq, last_seq + self._max)
            events = load_events(conn, last_seq + 1, to_seq)
            expected_head: ChainHead | None = head if to_seq == head.seq else None
            result = verify_chain(
                events,
                expected_seq=last_seq + 1,
                expected_prev_hash=last_hash,
                expected_head=expected_head,
            )
            if not result.ok:
                assert result.finding is not None
                raise ChainDivergence(result.finding)
            by_seq = {e.seq: e for e in events}
            anchors = anchors_in_range(conn, last_seq, to_seq)
            prev_anchor_hash = self._prev_anchor_hash(conn, anchors)
            for anchor in anchors:
                event = by_seq.get(anchor.chain_seq)
                if event is None or event.event_hash != anchor.head_hash:
                    raise ChainDivergence(
                        Finding(
                            FindingCode.HEAD_MISMATCH,
                            anchor.chain_seq,
                            "anchor head_hash != chain event_hash",
                        )
                    )
                if anchor.prev_anchor_hash != prev_anchor_hash:
                    raise ChainDivergence(
                        Finding(
                            FindingCode.CHAIN_BREAK, anchor.chain_seq, "anchor chain linkage broken"
                        )
                    )
                if not verify_anchor_signature(self._public_key, anchor):
                    raise ChainDivergence(
                        Finding(
                            FindingCode.HASH_MISMATCH, anchor.chain_seq, "anchor signature invalid"
                        )
                    )
                prev_anchor_hash = anchor.anchor_hash
            new_hash = events[-1].event_hash if events else last_hash
            conn.execute(_ADVANCE, {"seq": to_seq, "hash": new_hash, "at": self._clock()})
        return VerificationPass(
            from_seq=last_seq + 1,
            to_seq=to_seq,
            events_verified=len(events),
            anchors_verified=len(anchors),
        )

    @staticmethod
    def _prev_anchor_hash(conn: Connection, anchors: list[AnchorRecord]) -> bytes:
        if not anchors:
            return GENESIS_PREV_HASH
        previous = anchor_before(conn, anchors[0].anchor_seq)
        return GENESIS_PREV_HASH if previous is None else previous.anchor_hash
