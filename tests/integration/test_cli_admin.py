"""Operator CLI (Ch. 45) end to end: the real admin app, served in-process as the CLI's HTTP client."""

from __future__ import annotations

import io
import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
import redis
from fastapi.testclient import TestClient
from keystone_cli.client import AdminClient
from keystone_cli.main import main
from sqlalchemy.engine import Engine

from keystone.admin.app import create_admin_app
from keystone.admin.deps import AdminServices
from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import PostgresAuditSink
from keystone.authz.bundles import build_signed_bundle, inspect_bundle
from keystone.authz.evaluator import PolicyInput
from keystone.db.ids import uuid7
from tests.integration.test_admin_plane import BOOTSTRAP, _admin
from tests.integration.test_issuance_service_pg import ARN, TEMPLATE
from tests.integration.test_pin_activation_opa import POLICIES, _rsa_pair

pytestmark = pytest.mark.integration

Run = Callable[..., tuple[int, str]]


@pytest.fixture
def services(app_engine: Engine, redis_client: redis.Redis) -> AdminServices:
    return _admin(app_engine, redis_client)


@pytest.fixture
def run(services: AdminServices) -> Run:
    http = TestClient(create_admin_app(services))

    def invoke(*argv: str, token: str = BOOTSTRAP) -> tuple[int, str]:
        out = io.StringIO()
        code = main(
            list(argv), out, client_factory=lambda: AdminClient("http://testserver", token, http)
        )
        return code, out.getvalue()

    return invoke


def _json(run: Run, *argv: str) -> object:
    code, out = run(*argv, "--json")
    assert code == 0, out
    return json.loads(out)


def test_roles_lifecycle_through_the_cli(run: Run, tmp_path: Path) -> None:
    code, out = run("roles", "create", "deploy-prod", "--role-arn", ARN, "--max-ttl", "1800")
    assert code == 0 and "deploy-prod" in out

    code, out = run("roles", "list")
    assert code == 0
    header, row = out.splitlines()
    assert header.split() == ["NAME", "ENABLED", "MAX_TTL_SECONDS", "ROLE_ARN", "OWNER"]
    assert row.split()[:3] == ["deploy-prod", "True", "1800"]

    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(TEMPLATE))
    code, _ = run("roles", "add-policy", "deploy-prod", "--ref", "s3-deploy", "--file", str(policy))
    assert code == 0

    code, _ = run("roles", "update", "deploy-prod", "--disable", "--owner", "platform")
    assert code == 0
    role = _json(run, "roles", "get", "deploy-prod")
    assert isinstance(role, dict)
    assert role["enabled"] is False and role["owner"] == "platform"
    assert [p["ref"] for p in role["session_policies"]] == ["s3-deploy"]

    # Every mutation above was audited and is visible through `audit tail`.
    code, out = run("audit", "tail", "--after-seq", "0", "--type", "admin_role_changed", "--json")
    assert code == 0
    events = [json.loads(line) for line in out.splitlines()]
    assert len(events) == 3 and {e["event_type"] for e in events} == {"admin_role_changed"}


def test_server_rules_surface_as_exit_2_with_the_error_code(
    run: Run, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = run("roles", "create", "bad", "--role-arn", ARN, "--max-ttl", "60")
    assert code == 2
    assert "VALIDATION_FAILED (HTTP 400)" in capsys.readouterr().err
    code, _ = run("roles", "get", "nope")
    assert code == 2
    assert "REGISTRY_ROLE_UNKNOWN (HTTP 404)" in capsys.readouterr().err
    code, _ = run("roles", "update", "nope")
    assert code == 2 and "nothing to update" in capsys.readouterr().err
    code, _ = run("decisions", "get", "not-a-uuid")
    assert code == 2 and "not a UUID" in capsys.readouterr().err


def test_a_bad_token_is_exit_2_and_never_echoed(
    run: Run, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = run("roles", "list", token="wrong-" + "z" * 40)
    err = capsys.readouterr().err
    assert code == 2 and "ADMIN_TOKEN_INVALID (HTTP 401)" in err
    assert "z" * 40 not in err


def test_tokens_issue_list_revoke(run: Run) -> None:
    code, out = run("tokens", "issue", "--principal", "alice", "--ttl-days", "7")
    assert code == 0
    plaintext = out.split("token (shown once): ")[1].strip()
    assert len(plaintext) >= 32
    listed = _json(run, "tokens", "list")
    assert isinstance(listed, dict)
    assert plaintext not in json.dumps(listed)  # only the issue response ever carries it
    alice = next(t for t in listed["tokens"] if t["principal"] == "alice")
    code, _ = run("roles", "list", token=plaintext)
    assert code == 0  # the issued token works
    code, _ = run("tokens", "revoke", alice["id"])
    assert code == 0
    code, _ = run("roles", "list", token=plaintext)
    assert code == 2  # and is dead once revoked


def test_policy_status_without_a_pin_is_a_finding(run: Run) -> None:
    code, out = run("policy", "status")
    assert code == 1 and "NO PIN" in out
    code, out = run("policy", "history")
    assert code == 0 and out == "(none)\n"


def test_revoke_role_renders_the_runbook(run: Run) -> None:
    assert run("roles", "create", "deploy-prod", "--role-arn", ARN, "--max-ttl", "1800")[0] == 0
    code, out = run("revoke", "role", "deploy-prod")
    assert code == 0
    # Mechanism 3 is OFF by default: nothing applied, the whole deny document is printed.
    assert "applied" in out and "False" in out
    document = json.loads(out.split("deny policy to attach to the role (runbook):\n")[1])
    assert document["Statement"][0]["Effect"] == "Deny"


def test_decisions_tail_shows_only_decisions(run: Run, app_engine: Engine) -> None:
    sink = PostgresAuditSink()
    with app_engine.begin() as conn:
        for event_type in (EventType.DECISION_DENIED, EventType.ANCHOR_WRITTEN):
            sink.append(
                conn,
                AuditEventInput(
                    event_type=event_type,
                    occurred_at=datetime.now(UTC),
                    actor="repo:acme/app:ref:\x1b[31mmain",  # hostile claim text
                    data={"decision_id": str(uuid7()), "grant": "deploy-prod"},
                ),
            )
    code, out = run("decisions", "tail", "--after-seq", "0")
    assert code == 0
    lines = out.splitlines()
    assert len(lines) == 2 and "decision_denied" in lines[1]
    assert "\x1b" not in out and "\\x1b[31m" in out  # escaped, never interpreted


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH")
def test_replay_reproduces_and_counterfactuals(
    run: Run, app_engine: Engine, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key, _ = _rsa_pair(tmp_path, "signing")
    bundle_path = tmp_path / "bundle.tar.gz"
    bundle_path.write_bytes(build_signed_bundle(POLICIES, bundle_sequence=1, signing_key_pem=key))
    digest = inspect_bundle(bundle_path.read_bytes()).revision
    policy_input = PolicyInput.model_validate(
        {
            "schema": 1,
            "identity": {"repository": "acme/other", "ref": "refs/heads/main"},
            "request": {"grant": "deploy-prod", "requested_ttl_seconds": 900},
            "context": {"keystone_version": "0.1.0", "policy_version": digest},
        }
    )
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(policy_input.model_dump(by_alias=True)))

    def record(allowed: bool) -> str:
        decision_id = str(uuid7())
        with app_engine.begin() as conn:
            PostgresAuditSink().append(
                conn,
                AuditEventInput(
                    event_type=EventType.DECISION_ALLOWED if allowed else EventType.DECISION_DENIED,
                    occurred_at=datetime.now(UTC),
                    actor="repo:acme/other:ref:refs/heads/main",
                    input_hash=policy_input.input_hash(),
                    policy_digest=digest,
                    data={
                        "decision_id": decision_id,
                        "grant": "deploy-prod",
                        "rule_path": "keystone.grants.deploy_prod" if allowed else None,
                        "deny_reasons": [] if allowed else ["NO_GRANT_MATCHED"],
                        "ttl_cap_seconds": 900 if allowed else 0,
                        "session_policy_ref": "s3-deploy-narrow" if allowed else None,
                    },
                ),
            )
        return decision_id

    args = ("--bundle", str(bundle_path), "--input", str(input_path))
    denied = record(allowed=False)
    code, out = run("replay", denied, *args)
    assert code == 0, out
    assert "reproduction (same bundle)" in out and "decisions agree" in out

    # A record claiming the same input was allowed disagrees with the policy: exit 1.
    allowed = record(allowed=True)
    report = run("replay", allowed, *args, "--json")
    assert report[0] == 1
    body = json.loads(report[1])
    assert body["agree"] is False and body["mode"] == "reproduction"
    assert {f["field"] for f in body["fields"] if not f["match"]} >= {"allow", "deny_reasons"}

    # An input that is not the decided one is refused before anything is evaluated.
    other = tmp_path / "other.json"
    tampered = policy_input.model_dump(by_alias=True)
    tampered["identity"]["repository"] = "acme/app"
    other.write_text(json.dumps(tampered))
    code, _ = run("replay", denied, "--bundle", str(bundle_path), "--input", str(other))
    assert code == 2 and "input_hash differs" in capsys.readouterr().err
