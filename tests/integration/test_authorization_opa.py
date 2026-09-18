"""Authorization stage against a real OPA server loading the reference bundle, with PostgreSQL."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine

from keystone.audit.events import EventType
from keystone.audit.sink import PostgresAuditSink
from keystone.audit.store import load_events, snapshot_head
from keystone.audit.verify import verify_chain
from keystone.authz.evaluator import DecisionMalformed, OpaHttpEvaluator, PolicyInput
from keystone.authz.service import (
    AuthorizationService,
    Denied,
    NoActivePin,
    PolicyPinDivergence,
)
from keystone.broker.service import AuthorizedDecision
from keystone.db.ids import uuid7
from keystone.db.redis import DependencyUnavailable
from keystone.identity.oidc import VerifiedIdentity

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH"),
]

REPO = Path(__file__).resolve().parents[2]
REVISION = "sha256:" + "11" * 32


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def opa_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """`opa run --server` on a signed-revision bundle built from ./policies (tests excluded)."""
    build_dir = tmp_path_factory.mktemp("bundle")
    bundle = build_dir / "keystone.tar.gz"
    subprocess.run(
        [
            "opa",
            "build",
            "-b",
            str(REPO / "policies"),
            "--ignore",
            "*_test.rego",
            "-r",
            REVISION,
            "-o",
            str(bundle),
        ],
        check=True,
        capture_output=True,
    )
    port = _free_port()
    proc = subprocess.Popen(
        [
            "opa",
            "run",
            "--server",
            "--addr",
            f"127.0.0.1:{port}",
            "--log-level",
            "error",
            str(bundle),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if httpx.get(base + "/health", timeout=0.5).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    else:
        proc.kill()
        raise RuntimeError("opa did not start")
    yield base
    proc.kill()
    proc.wait()


def _identity(**overrides: Any) -> VerifiedIdentity:
    now = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)
    claims: dict[str, Any] = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "keystone-acme",
        "sub": "repo:acme/app:ref:refs/heads/main",
        "repository": "acme/app",
        "repository_owner": "acme",
        "repository_id": "42",
        "ref": "refs/heads/main",
        "sha": "abc",
        "workflow_ref": "acme/app/.github/workflows/deploy.yml@refs/heads/main",
        "job_workflow_ref": "acme/app/.github/workflows/deploy.yml@refs/heads/main",
        "run_id": "1234",
        "run_attempt": "1",
        "actor": "octocat",
        "event_name": "push",
        "jti": "j",
        "iat": int(now.timestamp()) - 5,
        "nbf": int(now.timestamp()) - 5,
        "exp": int(now.timestamp()) + 300,
    }
    claims.update(overrides)
    return VerifiedIdentity(
        sub=claims["sub"],
        repository=claims["repository"],
        repository_owner=claims["repository_owner"],
        repository_id=claims["repository_id"],
        ref=claims["ref"],
        workflow_ref=claims["workflow_ref"],
        run_id=claims["run_id"],
        actor=claims["actor"],
        event_name=claims["event_name"],
        jti_hash=bytes(32),
        kid="kid-1",
        issued_at=now,
        expires_at=now,
        verified_at=now,
        claims=claims,
    )


def _pin(engine: Engine, digest: str, active: bool = True) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO policy_pins (id, bundle_digest, bundle_sequence, active) "
                "VALUES (:id, :digest, 1, :active)"
            ),
            {"id": uuid7(), "digest": digest, "active": active},
        )


def _events(engine: Engine) -> list[Any]:
    with engine.connect() as conn:
        head = snapshot_head(conn)
        events = load_events(conn, 1, head.seq)
        assert verify_chain(events, expected_head=head).ok
    return events


def _service(engine: Engine, opa_server: str) -> AuthorizationService:
    return AuthorizationService(
        engine, PostgresAuditSink(), OpaHttpEvaluator(opa_server), keystone_version="0.1.0"
    )


def test_allow_is_audited_before_it_is_returned(app_engine: Engine, opa_server: str) -> None:
    _pin(app_engine, REVISION)
    service = _service(app_engine, opa_server)
    decision_id = uuid7()
    result = service.authorize(
        _identity(),
        grant="deploy-prod",
        requested_ttl_seconds=900,
        source_ip="10.0.0.1",
        decision_id=decision_id,
    )
    assert isinstance(result, AuthorizedDecision)
    assert result.grant == "deploy-prod" and result.session_policy_ref == "s3-deploy-narrow"
    assert result.policy_digest == REVISION and result.decision_audit_seq == 1
    events = _events(app_engine)
    assert events[0].event_type == EventType.DECISION_ALLOWED.value
    details = events[0].details
    assert details["policy_digest"] == REVISION and len(details["input_hash"]) == 64
    assert details["data"]["decision_id"] == str(decision_id)
    assert details["data"]["rule_path"] == "keystone.grants.deploy_prod"


def test_absent_claim_denies_with_a_reason(app_engine: Engine, opa_server: str) -> None:
    _pin(app_engine, REVISION)
    service = _service(app_engine, opa_server)
    identity = _identity()
    identity = identity.model_copy(
        update={"claims": {k: v for k, v in identity.claims.items() if k != "ref"}}
    )
    result = service.authorize(
        identity,
        grant="deploy-prod",
        requested_ttl_seconds=None,
        source_ip="x",
        decision_id=uuid7(),
    )
    assert isinstance(result, Denied) and result.reasons == ("NO_GRANT_MATCHED",)
    events = _events(app_engine)
    assert events[0].event_type == EventType.DECISION_DENIED.value
    assert events[0].details["data"]["deny_reasons"] == ["NO_GRANT_MATCHED"]


def test_wrong_type_claim_and_wrong_repo_deny(app_engine: Engine, opa_server: str) -> None:
    _pin(app_engine, REVISION)
    service = _service(app_engine, opa_server)
    for overrides in (
        {"ref": ["refs/heads/main"]},  # wrong type reaches the policy verbatim and must deny
        {"repository_owner": "evil"},
        {"event_name": "pull_request"},
    ):
        base = _identity()
        identity = base.model_copy(update={"claims": {**base.claims, **overrides}})
        result = service.authorize(
            identity,
            grant="deploy-prod",
            requested_ttl_seconds=None,
            source_ip="x",
            decision_id=uuid7(),
        )
        assert isinstance(result, Denied)


def test_pin_divergence_is_503_and_audited(app_engine: Engine, opa_server: str) -> None:
    _pin(app_engine, "sha256:" + "22" * 32)  # DB says a different bundle should be live
    service = _service(app_engine, opa_server)
    with pytest.raises(PolicyPinDivergence):
        service.authorize(
            _identity(),
            grant="deploy-prod",
            requested_ttl_seconds=None,
            source_ip="x",
            decision_id=uuid7(),
        )
    events = _events(app_engine)
    assert events[0].details["data"]["deny_reasons"] == ["POLICY_PIN_DIVERGENCE"]
    assert events[0].details["data"]["loaded_digest"] == REVISION


def test_no_active_pin_fails_closed(app_engine: Engine, opa_server: str) -> None:
    _pin(app_engine, REVISION, active=False)
    with pytest.raises(NoActivePin):
        _service(app_engine, opa_server).authorize(
            _identity(),
            grant="deploy-prod",
            requested_ttl_seconds=None,
            source_ip="x",
            decision_id=uuid7(),
        )
    assert _events(app_engine) == []


def test_opa_unreachable_is_503_not_allow(app_engine: Engine) -> None:
    _pin(app_engine, REVISION)
    evaluator = OpaHttpEvaluator(f"http://127.0.0.1:{_free_port()}")
    service = AuthorizationService(
        app_engine, PostgresAuditSink(), evaluator, keystone_version="0.1.0"
    )
    with pytest.raises(DependencyUnavailable):
        service.authorize(
            _identity(),
            grant="deploy-prod",
            requested_ttl_seconds=None,
            source_ip="x",
            decision_id=uuid7(),
        )


def test_undefined_decision_is_malformed_not_allow(opa_server: str) -> None:
    class Bare(OpaHttpEvaluator):
        pass

    evaluator = Bare(opa_server)
    evaluator._url = opa_server + "/v1/data/keystone/authz/no_such_rule"
    with pytest.raises(DecisionMalformed):
        evaluator.evaluate(PolicyInput(schema=1, identity={}, request={}, context={}))


def test_evaluator_refuses_non_local_opa() -> None:
    with pytest.raises(ValueError, match="localhost"):
        OpaHttpEvaluator("http://opa.internal:8181")
    assert os.environ.get("KEYSTONE_OPA_BIN", "") == "" or True
