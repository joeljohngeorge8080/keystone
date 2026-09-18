import time

from keystone.db.ids import uuid7


def test_uuid7_version_variant_and_timestamp() -> None:
    before_ms = time.time_ns() // 1_000_000
    value = uuid7()
    after_ms = time.time_ns() // 1_000_000
    assert value.version == 7
    assert value.variant == "specified in RFC 4122"
    assert before_ms <= value.int >> 80 <= after_ms


def test_uuid7_is_unique_and_time_ordered() -> None:
    values = [uuid7() for _ in range(1000)]
    assert len(set(values)) == 1000
    stamps = [v.int >> 80 for v in values]
    assert stamps == sorted(stamps)
