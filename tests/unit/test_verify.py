import json

from keystone.audit.chain import GENESIS_PREV_HASH, compute_event_hash
from keystone.audit.verify import ChainHead, FindingCode, verify_chain
from tests.unit.chainfixture import build_chain, replace


def test_intact_chain_verifies_to_head() -> None:
    events, head = build_chain(5)
    result = verify_chain(events, expected_head=head)
    assert result.ok and result.events_verified == 5 and result.last_verified_seq == 5


def test_empty_chain_with_genesis_head_is_ok() -> None:
    assert verify_chain([], expected_head=ChainHead(0, GENESIS_PREV_HASH)).ok


def test_sub_range_verifies_with_supplied_prev_hash() -> None:
    events, _ = build_chain(6)
    result = verify_chain(events[2:5], expected_seq=3, expected_prev_hash=events[1].event_hash)
    assert result.ok and result.events_verified == 3


def test_tampered_canonical_byte_is_hash_mismatch() -> None:
    events, head = build_chain(4)
    tampered = bytearray(events[2].canonical_payload)
    tampered[-3] ^= 0x01
    events[2] = replace(events[2], canonical_payload=bytes(tampered))
    result = verify_chain(events, expected_head=head)
    assert not result.ok
    assert result.finding is not None
    assert (result.finding.code, result.finding.seq) == (FindingCode.HASH_MISMATCH, 3)
    assert result.events_verified == 2


def test_tampered_details_projection_is_details_divergence() -> None:
    events, head = build_chain(4)
    forged = json.loads(events[1].canonical_payload)
    forged["actor"] = "someone-else"
    events[1] = replace(events[1], details=forged)
    result = verify_chain(events, expected_head=head)
    assert result.finding is not None
    assert (result.finding.code, result.finding.seq) == (FindingCode.DETAILS_DIVERGENCE, 2)


def test_details_absent_is_allowed() -> None:
    events, head = build_chain(3)
    events = [replace(e, details=None) for e in events]
    assert verify_chain(events, expected_head=head).ok


def test_deleted_middle_event_is_seq_gap() -> None:
    events, head = build_chain(5)
    del events[2]
    result = verify_chain(events, expected_head=head)
    assert result.finding is not None
    assert (result.finding.code, result.finding.seq) == (FindingCode.SEQ_GAP, 4)


def test_deleted_tail_is_head_mismatch() -> None:
    events, head = build_chain(5)
    result = verify_chain(events[:3], expected_head=head)
    assert result.finding is not None
    assert result.finding.code == FindingCode.HEAD_MISMATCH
    assert result.events_verified == 3


def test_reordered_events_with_renumbered_columns_are_caught() -> None:
    events, head = build_chain(4)
    a, b = events[1], events[2]
    # Attacker swaps two rows and rewrites the seq columns to hide it.
    events[1], events[2] = replace(b, seq=2), replace(a, seq=3)
    result = verify_chain(events, expected_head=head)
    assert result.finding is not None
    assert (result.finding.code, result.finding.seq) == (FindingCode.CHAIN_BREAK, 2)


def test_rehashed_forgery_is_caught_downstream() -> None:
    events, head = build_chain(3)
    forged_payload = events[0].canonical_payload.replace(b"actor-1", b"actor-X")
    forged_hash = compute_event_hash(GENESIS_PREV_HASH, forged_payload)
    events[0] = replace(
        events[0],
        canonical_payload=forged_payload,
        details=json.loads(forged_payload),
        event_hash=forged_hash,
    )
    result = verify_chain(events, expected_head=head)
    assert result.finding is not None
    assert (result.finding.code, result.finding.seq) == (FindingCode.CHAIN_BREAK, 2)


def test_column_projection_divergence_is_caught() -> None:
    events, head = build_chain(2)
    events[0] = replace(events[0], event_type="credential_issued")
    result = verify_chain(events, expected_head=head)
    assert result.finding is not None
    assert (result.finding.code, result.finding.seq) == (FindingCode.COLUMN_DIVERGENCE, 1)


def test_unparseable_canonical_is_reported_not_crashed() -> None:
    events, head = build_chain(2)
    junk = b"\xff\xfe not json"
    events[1] = replace(
        events[1],
        canonical_payload=junk,
        event_hash=compute_event_hash(events[0].event_hash, junk),
    )
    result = verify_chain(events, expected_head=head)
    assert result.finding is not None
    assert result.finding.code == FindingCode.CANONICAL_UNPARSEABLE
