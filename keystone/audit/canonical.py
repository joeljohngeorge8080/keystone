"""RFC 8785 (JCS) canonical bytes — the sole hashing and rendering source (R1)."""

import json

import rfc8785
from pydantic import JsonValue


def canonicalize(obj: JsonValue) -> bytes:
    return rfc8785.dumps(obj)


def decode_canonical(payload: bytes) -> JsonValue:
    decoded: JsonValue = json.loads(payload)
    return decoded
