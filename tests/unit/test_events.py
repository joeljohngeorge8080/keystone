import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from keystone.audit.events import (
    SCHEMA_VERSION,
    AuditEventInput,
    EventType,
    canonical_object,
    format_rfc3339,
)

NOW = datetime(2026, 9, 18, 12, 34, 56, 789012, tzinfo=UTC)


def test_canonical_object_shape_is_stable() -> None:
    event_id = uuid.UUID("01999999-0000-7000-8000-000000000001")
    event = AuditEventInput(
        event_type=EventType.DECISION_DENIED,
        occurred_at=NOW,
        actor="repo:acme/app:ref:refs/heads/main",
        input_hash="ab" * 32,
        policy_digest="sha256:deadbeef",
        data={"deny_reasons": ["NO_GRANT_MATCHED"]},
    )
    assert canonical_object(7, event_id, event) == {
        "schema_version": SCHEMA_VERSION,
        "seq": 7,
        "id": str(event_id),
        "event_type": "decision_denied",
        "occurred_at": "2026-09-18T12:34:56.789012Z",
        "actor": "repo:acme/app:ref:refs/heads/main",
        "issuance_id": None,
        "admin_principal_id": None,
        "input_hash": "ab" * 32,
        "policy_digest": "sha256:deadbeef",
        "data": {"deny_reasons": ["NO_GRANT_MATCHED"]},
    }


def test_rfc3339_is_fixed_precision_utc() -> None:
    ist = datetime(2026, 9, 18, 18, 4, 56, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    assert format_rfc3339(ist.astimezone(UTC)) == "2026-09-18T12:34:56.000000Z"


def test_naive_or_non_utc_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError, match="UTC"):
        AuditEventInput(
            event_type=EventType.AUTH_FAILED, occurred_at=NOW.replace(tzinfo=None), actor="x"
        )
    with pytest.raises(ValidationError, match="UTC"):
        AuditEventInput(
            event_type=EventType.AUTH_FAILED,
            occurred_at=NOW.astimezone(timezone(timedelta(hours=1))),
            actor="x",
        )


@pytest.mark.parametrize(
    "data",
    [
        {"SecretAccessKey": "x"},
        {"secret_access_key": "x"},
        {"session-token": "x"},
        {"nested": {"deep": [{"AccessKeyId": "AKIA..."}]}},
        {"Authorization": "Bearer ..."},
    ],
)
def test_credential_material_can_never_enter_the_audit_record(data: dict[str, object]) -> None:
    with pytest.raises(ValidationError, match="forbidden key"):
        AuditEventInput(
            event_type=EventType.CREDENTIAL_ISSUED,
            occurred_at=NOW,
            actor="x",
            data=data,  # type: ignore[arg-type]
        )


def test_access_key_prefix_is_allowed() -> None:
    event = AuditEventInput(
        event_type=EventType.CREDENTIAL_ISSUED,
        occurred_at=NOW,
        actor="x",
        data={"access_key_prefix": "AKIA"},
    )
    assert event.data == {"access_key_prefix": "AKIA"}


def test_strict_mode_rejects_coercion_and_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        AuditEventInput(event_type="decision_denied", occurred_at=NOW, actor="x")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        AuditEventInput(
            event_type=EventType.AUTH_FAILED,
            occurred_at=NOW,
            actor="x",
            extra=1,  # type: ignore[call-arg]
        )
    with pytest.raises(ValidationError):
        AuditEventInput(
            event_type=EventType.AUTH_FAILED, occurred_at=NOW, actor="x", input_hash="ZZ" * 32
        )
