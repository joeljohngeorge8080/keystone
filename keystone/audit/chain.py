"""Hash-chain primitive — spec Ch. 33: event_hash = SHA-256(prev_hash || canonical_payload)."""

import hashlib

HASH_LEN = 32
# Genesis constant (Ch. 33): the prev_hash of seq 1 and the initial audit_chain_head.head_hash.
GENESIS_PREV_HASH = bytes(HASH_LEN)


def compute_event_hash(prev_hash: bytes, canonical_payload: bytes) -> bytes:
    if len(prev_hash) != HASH_LEN:
        raise ValueError(f"prev_hash must be {HASH_LEN} bytes, got {len(prev_hash)}")
    return hashlib.sha256(prev_hash + canonical_payload).digest()
