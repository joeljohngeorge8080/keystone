"""RFC 8785 conformance: the canonical bytes must be exactly what JCS specifies."""

import json
import math

import pytest
import rfc8785
from pydantic import JsonValue

from keystone.audit.canonical import canonicalize, decode_canonical

# RFC 8785 section 3.2.3 worked example: input object and its exact canonical serialization.
RFC_EXAMPLE_INPUT = json.loads(
    '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
    ' "string": "\\u20ac$\\u000f\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\u002f",'
    ' "literals": [null, true, false]}'
)
RFC_EXAMPLE_OUTPUT = (
    b'{"literals":[null,true,false],'
    b'"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
    b'"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
)


def test_rfc8785_worked_example() -> None:
    assert canonicalize(RFC_EXAMPLE_INPUT) == RFC_EXAMPLE_OUTPUT


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1.0, b"1"),
        (100.0, b"100"),
        (0.1, b"0.1"),
        (1e21, b"1e+21"),
        (1e20, b"100000000000000000000"),
        (5e-7, b"5e-7"),
        (0.000001, b"0.000001"),
        (-0.0, b"0"),
        (2**53 - 1, b"9007199254740991"),
        (True, b"true"),
        (None, b"null"),
        ("é", '"é"'.encode()),
        ("\x7f", b'"\x7f"'),
        ("\x1f", b'"\\u001f"'),
    ],
)
def test_scalar_serialization(value: object, expected: bytes) -> None:
    assert canonicalize(value) == expected  # type: ignore[arg-type]


def test_keys_sorted_by_utf16_code_units_not_insertion_order() -> None:
    obj: JsonValue = {"b": 1, "a": 2, "A": 3, "é": 4, "\U0001d11e": 5, "～": 6}  # noqa: RUF001
    # UTF-16 units: A=0041 a=0061 b=0062 e-acute=00E9 G-clef=D834 DD1E fullwidth tilde=FF5E,
    # so the astral character sorts BEFORE U+FF5E (the opposite of code-point order).
    assert canonicalize(obj) == (
        b'{"A":3,"a":2,"b":1,"\xc3\xa9":4,"\xf0\x9d\x84\x9e":5,"\xef\xbd\x9e":6}'
    )


def test_no_whitespace_and_nested_determinism() -> None:
    a: JsonValue = {"z": [1, {"y": 2, "x": 3}], "a": {"c": None, "b": ""}}
    b: JsonValue = {"a": {"b": "", "c": None}, "z": [1, {"x": 3, "y": 2}]}
    assert canonicalize(a) == canonicalize(b) == b'{"a":{"b":"","c":null},"z":[1,{"x":3,"y":2}]}'


def test_round_trip_is_a_fixed_point() -> None:
    payload = canonicalize(RFC_EXAMPLE_INPUT)
    assert canonicalize(decode_canonical(payload)) == payload


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_are_rejected(bad: float) -> None:
    with pytest.raises(rfc8785.CanonicalizationError):
        canonicalize({"n": bad})


def test_integers_beyond_the_i_json_safe_domain_are_rejected() -> None:
    # audit_events.seq is BIGINT but JCS only admits |n| <= 2**53-1; ~9e15 events is unreachable.
    with pytest.raises(rfc8785.IntegerDomainError):
        canonicalize({"seq": 2**53})


def test_non_string_keys_are_rejected() -> None:
    with pytest.raises((rfc8785.CanonicalizationError, TypeError)):
        canonicalize({1: "x"})  # type: ignore[dict-item]
