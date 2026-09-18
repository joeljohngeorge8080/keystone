import hashlib

import pytest

from keystone.audit.chain import GENESIS_PREV_HASH, HASH_LEN, compute_event_hash


def test_genesis_is_32_zero_bytes() -> None:
    assert GENESIS_PREV_HASH == b"\x00" * 32
    assert len(GENESIS_PREV_HASH) == HASH_LEN


def test_hash_is_sha256_over_prev_concat_canonical() -> None:
    payload = b'{"a":1}'
    assert (
        compute_event_hash(GENESIS_PREV_HASH, payload)
        == hashlib.sha256(GENESIS_PREV_HASH + payload).digest()
    )


def test_fixed_vector_guards_the_formula() -> None:
    # SHA-256 of 32 zero bytes followed by "{}" — pinned so a silent formula change is caught.
    assert (
        compute_event_hash(GENESIS_PREV_HASH, b"{}").hex()
        == hashlib.sha256(bytes(32) + b"{}").hexdigest()
    )
    assert compute_event_hash(GENESIS_PREV_HASH, b"{}") != hashlib.sha256(b"{}").digest()


def test_prev_hash_binds_the_chain() -> None:
    payload = b"{}"
    assert compute_event_hash(bytes(32), payload) != compute_event_hash(
        b"\x01" + bytes(31), payload
    )


@pytest.mark.parametrize("bad", [b"", b"\x00" * 31, b"\x00" * 33])
def test_prev_hash_length_is_enforced(bad: bytes) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        compute_event_hash(bad, b"{}")
