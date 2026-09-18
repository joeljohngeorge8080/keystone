"""Audit chain against real PostgreSQL: append serialization, append-only enforcement, R1 checks."""

import io
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from keystone_cli.main import DATABASE_URL_ENV, main
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError

from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import NotInTransactionError, PostgresAuditSink
from keystone.audit.store import load_events, snapshot_head
from keystone.audit.verify import FindingCode, verify_chain

pytestmark = pytest.mark.integration


def _event(n: int, event_type: EventType = EventType.DECISION_ALLOWED) -> AuditEventInput:
    return AuditEventInput(
        event_type=event_type,
        occurred_at=datetime.now(UTC),
        actor=f"repo:acme/app#{n}",
        input_hash=f"{n:064x}",
        policy_digest="sha256:0000",
        data={"n": n, "access_key_prefix": "AKIA"},
    )


def _verify_all(engine: Engine) -> tuple[bool, FindingCode | None]:
    with engine.connect() as connection:
        head = snapshot_head(connection)
        events = load_events(connection, 1, head.seq)
    result = verify_chain(events, expected_head=head)
    return result.ok, None if result.finding is None else result.finding.code


def test_append_as_app_role_then_verify(app_engine: Engine) -> None:
    sink = PostgresAuditSink()
    with app_engine.begin() as connection:
        stored = [sink.append(connection, _event(i)) for i in range(1, 4)]
    assert [s.seq for s in stored] == [1, 2, 3]
    assert stored[0].prev_hash == bytes(32)
    assert stored[1].prev_hash == stored[0].event_hash
    assert _verify_all(app_engine) == (True, None)
    with app_engine.connect() as connection:
        assert snapshot_head(connection).head_hash == stored[2].event_hash
        details_row = connection.execute(
            text("SELECT details, canonical_payload FROM audit_events WHERE seq = 2")
        ).one()
    assert details_row.details == json.loads(bytes(details_row.canonical_payload))


def test_append_outside_transaction_is_refused(app_engine: Engine) -> None:
    with app_engine.connect() as connection, pytest.raises(NotInTransactionError):
        PostgresAuditSink().append(connection, _event(1))


def test_rolled_back_business_transaction_leaves_no_event(app_engine: Engine) -> None:
    sink = PostgresAuditSink()
    with app_engine.connect() as connection:
        with connection.begin():
            sink.append(connection, _event(1))
        transaction = connection.begin()
        sink.append(connection, _event(2))
        transaction.rollback()
    with app_engine.connect() as connection:
        assert snapshot_head(connection).seq == 1
    assert _verify_all(app_engine) == (True, None)


def test_concurrent_appends_serialize_into_a_contiguous_chain(app_engine: Engine) -> None:
    sink = PostgresAuditSink()
    per_thread, threads = 25, 4
    errors: list[BaseException] = []

    def worker(offset: int) -> None:
        try:
            for i in range(per_thread):
                with app_engine.begin() as connection:
                    sink.append(connection, _event(offset + i))
        except BaseException as exc:  # noqa: BLE001 — surfaced via the errors list
            errors.append(exc)

    pool = [threading.Thread(target=worker, args=(t * 1000,)) for t in range(threads)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()
    assert errors == []
    with app_engine.connect() as connection:
        head = snapshot_head(connection)
        seqs = [
            row[0] for row in connection.execute(text("SELECT seq FROM audit_events ORDER BY seq"))
        ]
    assert head.seq == per_thread * threads
    assert seqs == list(range(1, per_thread * threads + 1))
    assert _verify_all(app_engine) == (True, None)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET details = '{}'::jsonb WHERE seq = 1",
        "DELETE FROM audit_events WHERE seq = 1",
        "TRUNCATE audit_events",
    ],
)
def test_app_role_cannot_rewrite_history(app_engine: Engine, statement: str) -> None:
    with app_engine.begin() as connection:
        PostgresAuditSink().append(connection, _event(1))
    with app_engine.begin() as connection, pytest.raises(DBAPIError, match="permission denied"):
        connection.execute(text(statement))


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET details = '{}'::jsonb WHERE seq = 1",
        "DELETE FROM audit_events WHERE seq = 1",
        "TRUNCATE audit_events",
    ],
)
def test_even_the_owner_is_blocked_by_the_append_only_trigger(
    admin_engine: Engine, app_engine: Engine, statement: str
) -> None:
    with app_engine.begin() as connection:
        PostgresAuditSink().append(connection, _event(1))
    with admin_engine.begin() as connection, pytest.raises(DBAPIError, match="append-only"):
        connection.execute(text(statement))


def _tamper_as_owner(admin_engine: Engine, statement: str) -> None:
    # Simulates a DB operator bypassing the trigger (threat P5): the verifier must still catch it.
    with admin_engine.begin() as connection:
        connection.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_rewrite"))
        connection.execute(text(statement))
        connection.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_rewrite"))


def test_details_tamper_is_details_divergence(admin_engine: Engine, app_engine: Engine) -> None:
    with app_engine.begin() as connection:
        for i in range(1, 4):
            PostgresAuditSink().append(connection, _event(i))
    _tamper_as_owner(
        admin_engine,
        "UPDATE audit_events SET details = jsonb_set(details, '{actor}', '\"mallory\"') "
        "WHERE seq = 2",
    )
    assert _verify_all(app_engine) == (False, FindingCode.DETAILS_DIVERGENCE)


def test_canonical_tamper_is_hash_mismatch(admin_engine: Engine, app_engine: Engine) -> None:
    with app_engine.begin() as connection:
        for i in range(1, 4):
            PostgresAuditSink().append(connection, _event(i))
    _tamper_as_owner(
        admin_engine,
        "UPDATE audit_events SET canonical_payload = "
        "convert_to(replace(convert_from(canonical_payload, 'UTF8'), 'acme', 'evil'), 'UTF8') "
        "WHERE seq = 3",
    )
    assert _verify_all(app_engine) == (False, FindingCode.HASH_MISMATCH)


def test_cli_verify_and_offline_export_roundtrip(
    app_engine: Engine, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with app_engine.begin() as connection:
        for i in range(1, 6):
            PostgresAuditSink().append(connection, _event(i))
    monkeypatch.setenv(DATABASE_URL_ENV, app_engine.url.render_as_string(hide_password=False))

    out = io.StringIO()
    assert main(["audit", "verify"], out=out) == 0
    assert out.getvalue().startswith("OK: 5 events verified")

    export = io.StringIO()
    assert main(["audit", "export"], out=export) == 0
    export_path = str(tmp_path / "chain.jsonl")
    with open(export_path, "w", encoding="utf-8") as handle:
        handle.write(export.getvalue())

    offline = io.StringIO()
    assert main(["audit", "verify", "--offline", export_path, "--json"], out=offline) == 0
    assert json.loads(offline.getvalue())["ok"] is True

    lines = export.getvalue().splitlines()
    record = json.loads(lines[3])
    record["details"]["actor"] = "mallory"
    lines[3] = json.dumps(record)
    with open(export_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    tampered = io.StringIO()
    assert main(["audit", "verify", "--offline", export_path], out=tampered) == 1
    assert "DETAILS_DIVERGENCE at seq 3" in tampered.getvalue()


def test_exponent_floats_in_data_do_not_false_positive(app_engine: Engine) -> None:
    event = AuditEventInput(
        event_type=EventType.CREDENTIAL_ISSUED,
        occurred_at=datetime.now(UTC),
        actor="x",
        data={"big": 1e30, "tiny": 1e-27, "plain": 4.5, "n": 2**53 - 1},
    )
    with app_engine.begin() as connection:
        PostgresAuditSink().append(connection, event)
    assert _verify_all(app_engine) == (True, None)


def test_cli_range_beyond_head_is_a_usage_error(
    app_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    with app_engine.begin() as connection:
        PostgresAuditSink().append(connection, _event(1))
    monkeypatch.setenv(DATABASE_URL_ENV, app_engine.url.render_as_string(hide_password=False))
    assert main(["audit", "verify", "--from", "2"], out=io.StringIO()) == 0  # empty tail is fine
    assert main(["audit", "verify", "--from", "3"], out=io.StringIO()) == 2


def test_cli_refuses_credentials_on_argv_and_needs_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DATABASE_URL_ENV, raising=False)
    assert main(["audit", "verify"], out=io.StringIO()) == 2
