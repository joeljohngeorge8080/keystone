"""Migration 0002 constraints enforce the spec at the database, not just in Python."""

import uuid
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, IntegrityError

from keystone.db.ids import uuid7
from keystone.db.partitions import ensure_audit_partition_as_app

pytestmark = pytest.mark.integration

ARN = "arn:aws:iam::123456789012:role/keystone-deploy-prod"


def _role(
    engine: Engine, name: str = "deploy-prod", max_ttl: int = 3600, arn: str = ARN
) -> uuid.UUID:
    role_id = uuid7()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO target_roles (id, name, role_arn, max_ttl_seconds) "
                "VALUES (:id, :name, :arn, :ttl)"
            ),
            {"id": role_id, "name": name, "arn": arn, "ttl": max_ttl},
        )
    return role_id


def _pin(engine: Engine, sequence: int = 1, active: bool = True) -> uuid.UUID:
    pin_id = uuid7()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO policy_pins (id, bundle_digest, bundle_sequence, active) "
                "VALUES (:id, :digest, :seq, :active)"
            ),
            {"id": pin_id, "digest": "sha256:" + "ab" * 32, "seq": sequence, "active": active},
        )
    return pin_id


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("max_ttl_seconds", 899),
        ("max_ttl_seconds", 3601),
        ("name", "Bad Name"),
        ("role_arn", "arn:aws:iam::1:role/x"),
    ],
)
def test_target_roles_checks(app_engine: Engine, column: str, value: object) -> None:
    params = {"id": uuid7(), "name": "deploy-prod", "arn": ARN, "ttl": 900}
    key = {"max_ttl_seconds": "ttl", "name": "name", "role_arn": "arn"}[column]
    params[key] = value
    with app_engine.begin() as conn, pytest.raises(IntegrityError):
        conn.execute(
            text(
                "INSERT INTO target_roles (id, name, role_arn, max_ttl_seconds) VALUES (:id, :name, :arn, :ttl)"
            ),
            params,
        )


def test_only_one_active_policy_pin(app_engine: Engine) -> None:
    _pin(app_engine, 1, active=True)
    _pin(app_engine, 0, active=False)
    with pytest.raises(IntegrityError):
        _pin(app_engine, 2, active=True)


def test_inline_session_policy_capped_at_2048_chars(app_engine: Engine) -> None:
    role_id = _role(app_engine)
    with app_engine.begin() as conn, pytest.raises(IntegrityError):
        conn.execute(
            text(
                "INSERT INTO session_policy_templates (id, target_role_id, ref, policy_document) "
                "VALUES (:id, :role, 'wide', CAST(:doc AS jsonb))"
            ),
            {"id": uuid7(), "role": role_id, "doc": '{"Sid": "' + "x" * 2100 + '"}'},
        )


def _issuance_params(
    role_id: uuid.UUID, pin_id: uuid.UUID, **overrides: object
) -> dict[str, object]:
    params: dict[str, object] = {
        "id": uuid7(),
        "jti": bytes(32),
        "role": role_id,
        "pin": pin_id,
        "state": "authorized",
        "grant": "deploy-prod",
        "session": "ks-1-2-3",
        "ttl": 900,
        "claims": "{}",
    }
    params.update(overrides)
    return params


_INSERT_ISSUANCE = text(
    "INSERT INTO issuances (id, jti_hash, target_role_id, policy_pin_id, state, grant_name, "
    "session_name, granted_ttl_seconds, identity_claims) VALUES (:id, :jti, :role, :pin, :state, "
    ":grant, :session, :ttl, CAST(:claims AS jsonb))"
)


@pytest.mark.parametrize(
    "overrides",
    [
        {"state": "minted"},
        {"ttl": 899},
        {"ttl": 3601},
        {"jti": bytes(31)},
        {"session": "x"},
    ],
)
def test_issuance_checks(app_engine: Engine, overrides: dict[str, object]) -> None:
    role_id, pin_id = _role(app_engine), _pin(app_engine)
    with app_engine.begin() as conn, pytest.raises(IntegrityError):
        conn.execute(_INSERT_ISSUANCE, _issuance_params(role_id, pin_id, **overrides))


def test_jti_and_session_name_are_unique_join_keys(app_engine: Engine) -> None:
    role_id, pin_id = _role(app_engine), _pin(app_engine)
    with app_engine.begin() as conn:
        conn.execute(_INSERT_ISSUANCE, _issuance_params(role_id, pin_id))
    with app_engine.begin() as conn, pytest.raises(IntegrityError):  # replayed jti
        conn.execute(_INSERT_ISSUANCE, _issuance_params(role_id, pin_id, session="ks-9-9-9"))
    with app_engine.begin() as conn, pytest.raises(IntegrityError):  # duplicate session name
        conn.execute(_INSERT_ISSUANCE, _issuance_params(role_id, pin_id, jti=b"\x01" * 32))


def test_audit_event_issuance_fk_and_role_restrict(
    app_engine: Engine, admin_engine: Engine
) -> None:
    role_id, pin_id = _role(app_engine), _pin(app_engine)
    with app_engine.begin() as conn:
        conn.execute(_INSERT_ISSUANCE, _issuance_params(role_id, pin_id))
    with (
        admin_engine.begin() as conn,
        pytest.raises(IntegrityError),
    ):  # issuance references the role
        conn.execute(text("DELETE FROM target_roles WHERE id = :id"), {"id": role_id})
    with app_engine.begin() as conn, pytest.raises(IntegrityError):  # dangling issuance_id
        conn.execute(
            text(
                "INSERT INTO audit_events (seq, id, event_type, issuance_id, occurred_at, "
                "canonical_payload, prev_hash, event_hash) VALUES (1, :id, 'x', :iss, now(), "
                "'{}', :h, :h)"
            ),
            {"id": uuid7(), "iss": uuid7(), "h": bytes(32)},
        )


def test_app_role_cannot_delete_issuances_or_rewrite_anchors(
    app_engine: Engine, admin_engine: Engine
) -> None:
    role_id, pin_id = _role(app_engine), _pin(app_engine)
    with app_engine.begin() as conn:
        conn.execute(_INSERT_ISSUANCE, _issuance_params(role_id, pin_id))
    with app_engine.begin() as conn, pytest.raises(DBAPIError, match="permission denied"):
        conn.execute(text("DELETE FROM issuances"))
    with app_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_anchors (chain_seq, head_hash, prev_anchor_hash, anchored_at, signature) "
                "VALUES (0, :h, :h, now(), :sig)"
            ),
            {"h": bytes(32), "sig": bytes(64)},
        )
    with admin_engine.begin() as conn, pytest.raises(DBAPIError, match="append-only"):
        conn.execute(text("UPDATE audit_anchors SET external_ref = 'x'"))
    with admin_engine.begin() as conn, pytest.raises(DBAPIError, match="append-only"):
        conn.execute(text("DELETE FROM audit_anchors"))


def _months_from_now(months: int) -> date:
    today = datetime.now(UTC).date()
    index = today.year * 12 + today.month - 1 + months
    return date(index // 12, index % 12 + 1, 1)


def test_app_role_pre_creates_partitions_only_through_the_definer_function(
    app_engine: Engine,
) -> None:
    month = _months_from_now(20)  # beyond the 14 months seeded by migration 0001
    with app_engine.begin() as conn:
        assert ensure_audit_partition_as_app(conn, month) is True
        assert ensure_audit_partition_as_app(conn, month) is False  # idempotent
    with app_engine.connect() as conn:
        name = f"audit_events_{month.year:04d}{month.month:02d}"
        assert conn.execute(text("SELECT to_regclass(:n)"), {"n": name}).scalar() == name
    # Direct DDL is still refused: the function is the only door.
    with pytest.raises(DBAPIError, match="permission denied"), app_engine.begin() as conn:
        conn.execute(text("CREATE TABLE sneaky (id int)"))


@pytest.mark.parametrize(
    "month_sql",
    [
        "date '2001-01-01'",  # far past
        "(date_trunc('month', now()) + interval '30 months')::date",  # beyond the window
        "(date_trunc('month', now()) + interval '2 months' + interval '3 days')::date",
        "NULL",
    ],
)
def test_partition_function_refuses_out_of_window_or_odd_months(
    app_engine: Engine, month_sql: str
) -> None:
    with pytest.raises(DBAPIError), app_engine.begin() as conn:
        conn.execute(text(f"SELECT keystone_ensure_audit_partition({month_sql})"))
