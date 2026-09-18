import pytest
from pydantic import JsonValue

from keystone.audit.verify import json_equal


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (1e30, 10**30),  # PostgreSQL prints jsonb numerics without exponents
        (1e21, 1000000000000000000000),
        (4.5, 4.5),
        (1e-27, 1e-27),
        ({"n": [1e30, {"m": 0.002}]}, {"n": [10**30, {"m": 0.002}]}),
        (None, None),
        ("x", "x"),
    ],
)
def test_same_number_different_python_type_is_equal(a: JsonValue, b: JsonValue) -> None:
    assert json_equal(a, b)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (1e30, 10**30 + 1),  # a single low-order digit tamper is still caught
        (1, True),
        (True, 1),
        (0, False),
        ("1", 1),
        (1.0, "1"),
        ([1, 2], [2, 1]),
        ({"a": 1}, {"a": 1, "b": 2}),
        ({"a": 1}, {"b": 1}),
        (None, 0),
    ],
)
def test_different_values_are_not_equal(a: JsonValue, b: JsonValue) -> None:
    assert not json_equal(a, b)
