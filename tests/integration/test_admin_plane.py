"""Admin plane against real PostgreSQL and Redis; the policy flow with a real OPA sidecar polling
the admin app's bundle route over HTTP (served by uvicorn) with the dedicated bundle bearer."""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import redis
import uvicorn
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import Engine

from keystone.admin.app import BUNDLE_PATH, build_admin, create_admin_app
from keystone.admin.deps import AdminServices
from keystone.admin.readiness import ReadinessProbe
from keystone.admin.tokens import BOOTSTRAP_PRINCIPAL
from keystone.audit.anchor import AnchorBreaker
from keystone.audit.events import EventType
from keystone.audit.store import load_events, snapshot_head
from keystone.audit.verify import verify_chain
from keystone.authz.bundles import build_signed_bundle
from keystone.authz.pins import opa_config_yaml
from keystone.config.settings import Settings
from keystone.identity.jwks import JwksCache
from tests.integration.test_oidc_forgery_suite import FakeOrigin, KeyPair
from tests.integration.test_pin_activation_opa import POLICIES, _free_port, _rsa_pair

pytestmark = pytest.mark.integration

BOOTSTRAP = "bootstrap-" + "x" * 40
BUNDLE_TOKEN = "bundle-" + "y" * 40


def _settings(engine: Engine, client: redis.Redis, opa_port: int) -> Settings:
    kwargs = client.connection_pool.connection_kwargs
    return Settings(
        database_url=engine.url.render_as_string(hide_password=False),
        redis_url=f"redis://{kwargs['host']}:{kwargs['port']}/{kwargs.get('db', 0)}",
        aws_region="eu-west-1",
        oidc_audience="keystone-test",
        opa_url=f"http://127.0.0.1:{opa_port}",
        admin_bootstrap_token=BOOTSTRAP,
        bundle_service_token=BUNDLE_TOKEN,
        clock_sync_check=False,  # host-dependent; covered with an injected signal below
    )


def _admin(engine: Engine, client: redis.Redis, opa_port: int | None = None) -> AdminServices:
    services = build_admin(_settings(engine, client, opa_port or _free_port()))
    assert services.tokens.bootstrap(BOOTSTRAP) is not None
    return services


def _auth(token: str = BOOTSTRAP) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _chain(engine: Engine) -> list[Any]:
    with engine.connect() as conn:
        head = snapshot_head(conn)
        events = load_events(conn, 1, head.seq)
        assert verify_chain(events, expected_head=head).ok
    return events


@pytest.fixture
def client(app_engine: Engine, redis_client: redis.Redis) -> TestClient:
    return TestClient(create_admin_app(_admin(app_engine, redis_client)))


# ---- bootstrap and authentication ----


def test_bootstrap_registers_once_and_is_audited(
    app_engine: Engine, redis_client: redis.Redis
) -> None:
    services = build_admin(_settings(app_engine, redis_client, _free_port()))
    record = services.tokens.bootstrap(BOOTSTRAP)
    assert record is not None and record.principal == BOOTSTRAP_PRINCIPAL
    assert (record.expires_at - record.created_at).total_seconds() == 24 * 3600
    assert services.tokens.bootstrap(BOOTSTRAP) is None  # principals exist: never again
    assert services.tokens.authenticate(BOOTSTRAP).name == BOOTSTRAP_PRINCIPAL
    events = _chain(app_engine)
    assert [e.event_type for e in events] == [EventType.ADMIN_TOKEN_ISSUED.value]
    assert events[0].details["data"]["bootstrap"] is True
    with app_engine.connect() as conn:
        stored = conn.execute(text("SELECT token_hash FROM admin_tokens")).scalar_one()
    assert BOOTSTRAP.encode() not in bytes(stored) and len(bytes(stored)) == 32


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer"},
        {"Authorization": f"Basic {BOOTSTRAP}"},
        {"Authorization": "Bearer " + "z" * 40},
        {"Authorization": "Bearer short"},
    ],
)
def test_admin_routes_require_a_valid_bearer(client: TestClient, headers: dict[str, str]) -> None:
    response = client.get("/v1/admin/tokens", headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "ADMIN_TOKEN_INVALID"
    assert response.headers["cache-control"] == "no-store"


def test_expired_token_and_disabled_principal_are_rejected(
    client: TestClient, admin_engine: Engine
) -> None:
    assert client.get("/v1/admin/tokens", headers=_auth()).status_code == 200
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE admin_principals SET enabled = false"))
    assert client.get("/v1/admin/tokens", headers=_auth()).status_code == 401
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE admin_principals SET enabled = true"))
        conn.execute(
            text(
                "UPDATE admin_tokens SET created_at = now() - interval '2 days', "
                "expires_at = now() - interval '1 second'"
            )
        )
    assert client.get("/v1/admin/tokens", headers=_auth()).status_code == 401


# ---- tokens ----


def test_issue_list_revoke_token_lifecycle(client: TestClient, app_engine: Engine) -> None:
    issued = client.post(
        "/v1/admin/tokens", json={"principal": "ops.alice", "ttl_days": 7}, headers=_auth()
    )
    assert issued.status_code == 201, issued.text
    body = issued.json()
    token = body["token"]
    assert token.startswith("ksa_") and body["principal"] == "ops.alice"

    listed = client.get("/v1/admin/tokens", headers=_auth(token))
    assert listed.status_code == 200
    assert token not in listed.text and "token_hash" not in listed.text
    assert {t["principal"] for t in listed.json()["tokens"]} == {BOOTSTRAP_PRINCIPAL, "ops.alice"}

    # The new principal revokes the bootstrap token, as the runbook says to.
    bootstrap_id = next(
        t["id"] for t in listed.json()["tokens"] if t["principal"] == BOOTSTRAP_PRINCIPAL
    )
    revoked = client.delete(f"/v1/admin/tokens/{bootstrap_id}", headers=_auth(token))
    assert revoked.status_code == 200 and revoked.json()["revoked_at"] is not None
    assert client.get("/v1/admin/tokens", headers=_auth()).status_code == 401
    again = client.delete(f"/v1/admin/tokens/{bootstrap_id}", headers=_auth(token))
    assert again.status_code == 200  # idempotent, not re-audited

    events = _chain(app_engine)
    assert [e.event_type for e in events] == [
        EventType.ADMIN_TOKEN_ISSUED.value,  # bootstrap
        EventType.ADMIN_TOKEN_ISSUED.value,
        EventType.ADMIN_TOKEN_REVOKED.value,
    ]
    assert events[1].details["actor"] == BOOTSTRAP_PRINCIPAL
    assert events[1].details["admin_principal_id"] is not None
    assert events[2].details["actor"] == "ops.alice"
    assert all(token not in e.canonical_payload.decode() for e in events)


@pytest.mark.parametrize(
    "body",
    [
        {"principal": "ops.alice", "ttl_days": 91},
        {"principal": "ops.alice", "ttl_days": 0},
        {"principal": "Ops Alice"},
        {"principal": "ops.alice", "extra": True},
    ],
)
def test_issue_token_validation(client: TestClient, body: dict[str, Any]) -> None:
    response = client.post("/v1/admin/tokens", json=body, headers=_auth())
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_FAILED"


def test_revoke_unknown_or_malformed_id(client: TestClient) -> None:
    missing = client.delete(
        "/v1/admin/tokens/00000000-0000-7000-8000-000000000000", headers=_auth()
    )
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "ADMIN_TOKEN_NOT_FOUND"
    malformed = client.delete("/v1/admin/tokens/not-a-uuid", headers=_auth())
    assert malformed.status_code == 400
    assert malformed.json()["error"]["code"] == "VALIDATION_FAILED"


# ---- bundle route and pin upload validation ----


def test_bundle_route_accepts_only_the_bundle_bearer(client: TestClient) -> None:
    assert client.get(BUNDLE_PATH).status_code == 401
    assert client.get(BUNDLE_PATH, headers=_auth()).status_code == 401  # admin token is not it
    assert client.get(BUNDLE_PATH, headers=_auth(BUNDLE_TOKEN + "x")).status_code == 401
    nothing = client.get(BUNDLE_PATH, headers=_auth(BUNDLE_TOKEN))
    assert nothing.status_code == 404
    assert nothing.json()["error"]["code"] == "BUNDLE_NOT_STAGED"


def test_pin_upload_rejects_bad_content(client: TestClient) -> None:
    wrong_type = client.post(
        "/v1/policy/pins", content=b"{}", headers={**_auth(), "Content-Type": "application/json"}
    )
    assert wrong_type.status_code == 415
    garbage = client.post(
        "/v1/policy/pins",
        content=b"not a tarball",
        headers={**_auth(), "Content-Type": "application/gzip"},
    )
    assert garbage.status_code == 400
    assert garbage.json()["error"]["code"] == "POLICY_BUNDLE_INVALID"
    unauthenticated = client.post(
        "/v1/policy/pins", content=b"x", headers={"Content-Type": "application/gzip"}
    )
    assert unauthenticated.status_code == 401


# ---- readiness ----


def test_readyz_enumerates_degraded_states_without_auth(client: TestClient) -> None:
    response = client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["checks"]["postgres"] == "ok" and body["checks"]["redis"] == "ok"
    assert body["checks"]["policy"] == "no_active_pin"
    assert body["checks"]["jwks"] == "cold"
    assert body["checks"]["anchor_breaker"] == "ok"
    assert body["degraded"] == ["jwks", "policy"]
    assert "sha256:" not in response.text


def test_readyz_reports_redis_down(app_engine: Engine, redis_client: redis.Redis) -> None:
    services = _admin(app_engine, redis_client)
    dead = build_admin(
        _settings(app_engine, redis_client, _free_port()).model_copy(
            update={"redis_url": "redis://127.0.0.1:1/0"}
        )
    )
    probe_client = TestClient(create_admin_app(dead))
    body = probe_client.get("/readyz").json()
    assert body["checks"]["redis"] == "unreachable"
    assert body["checks"]["jwks"] == body["checks"]["anchor_breaker"] == "unknown"
    assert services.tokens.list()  # the healthy instance is unaffected


@pytest.mark.parametrize(("signal", "ready"), [("ok", True), ("unsynced", False)])
def test_readyz_degrades_on_clock_desync(
    app_engine: Engine, redis_client: redis.Redis, signal: str, ready: bool
) -> None:
    services = _admin(app_engine, redis_client)
    probe = ReadinessProbe(
        app_engine,
        redis_client,
        services.gateway,
        JwksCache(redis_client, FakeOrigin(KeyPair("kid-1"))),
        AnchorBreaker(redis_client, threshold=timedelta(minutes=10)),
        clock_sync=lambda: signal,
    )
    readiness = probe.check()
    assert readiness.checks["clock"] == signal
    assert ("clock" in readiness.degraded) is not ready


# ---- full policy flow with a real OPA sidecar ----


@dataclass
class Live:
    base: str
    services: AdminServices
    signing_key: Path


@pytest.fixture
def live(app_engine: Engine, redis_client: redis.Redis, tmp_path: Path) -> Iterator[Live]:
    if shutil.which("opa") is None:
        pytest.skip("opa not on PATH")
    signing_key, public_pem = _rsa_pair(tmp_path, "signing")
    admin_port, opa_port = _free_port(), _free_port()
    services = _admin(app_engine, redis_client, opa_port)
    server = uvicorn.Server(
        uvicorn.Config(
            create_admin_app(services), host="127.0.0.1", port=admin_port, log_level="error"
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    token_file = tmp_path / "bundle-token"
    token_file.write_text(BUNDLE_TOKEN)
    config = tmp_path / "opa.yaml"
    config.write_text(
        opa_config_yaml(
            bundle_service_url=f"http://127.0.0.1:{admin_port}",
            resource=BUNDLE_PATH.lstrip("/"),
            verification_key_pem=public_pem,
            poll_seconds=1,
            bearer_token_path=str(token_file),
        )
    )
    opa = subprocess.Popen(
        [
            "opa",
            "run",
            "--server",
            "--addr",
            f"127.0.0.1:{opa_port}",
            "--log-level",
            "error",
            "-c",
            str(config),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{admin_port}"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not server.started:
        time.sleep(0.05)
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{opa_port}/health", timeout=0.5).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    try:
        yield Live(base=base, services=services, signing_key=signing_key)
    finally:
        opa.kill()
        opa.wait()
        server.should_exit = True
        thread.join(timeout=5)


def test_pin_activation_through_the_admin_plane(
    live: Live, app_engine: Engine, redis_client: redis.Redis
) -> None:
    bundle = build_signed_bundle(POLICIES, bundle_sequence=3, signing_key_pem=live.signing_key)
    with httpx.Client(base_url=live.base, timeout=40) as http:
        response = http.post(
            "/v1/policy/pins",
            content=bundle,
            headers={**_auth(), "Content-Type": "application/gzip"},
        )
        assert response.status_code == 201, response.text
        pin = response.json()
        assert pin["bundle_sequence"] == 3 and pin["rolled_back"] is False

        status = http.get("/v1/policy/status", headers=_auth()).json()
        assert status["divergent"] is False
        assert status["loaded_digest"] == pin["bundle_digest"]

        history = http.get("/v1/policy/pins", headers=_auth()).json()["pins"]
        assert history[0]["active"] is True and history[0]["pinned_by"] == BOOTSTRAP_PRINCIPAL

        # Same sequence, different content: refused without force_rollback (R8).
        stale = http.post(
            "/v1/policy/pins",
            content=build_signed_bundle(
                POLICIES / "keystone" / "grants",
                bundle_sequence=3,
                signing_key_pem=live.signing_key,
            ),
            headers={**_auth(), "Content-Type": "application/gzip"},
        )
        assert stale.status_code == 409
        assert stale.json()["error"]["code"] == "POLICY_PIN_SEQUENCE_REJECTED"

        # With a pin loaded and JWKS warm, the instance reports ready.
        JwksCache(redis_client, FakeOrigin(KeyPair("kid-1")), sleep=lambda _: None).prefetch()
        ready = http.get("/readyz")
        assert ready.status_code == 200, ready.text
        assert ready.json()["degraded"] == []

    events = _chain(app_engine)
    pinned = [e for e in events if e.event_type == EventType.ADMIN_POLICY_PINNED.value]
    assert len(pinned) == 1
    assert pinned[0].details["actor"] == BOOTSTRAP_PRINCIPAL
    assert pinned[0].details["admin_principal_id"] is not None
