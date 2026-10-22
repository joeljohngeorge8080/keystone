"""POST /v1/credentials end to end: real PostgreSQL, Redis and OPA; fake JWKS origin and connector."""

from __future__ import annotations

import shutil
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
import redis
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import Engine

from keystone.api.app import create_app
from keystone.api.credentials import CredentialPipeline
from keystone.api.ratelimit import (
    BucketPolicy,
    StsInflightGuard,
    Tier0Shedder,
    Tier1Limiter,
    TokenBuckets,
)
from keystone.audit.aggregation import FailureAggregator
from keystone.audit.events import EventType
from keystone.audit.sink import PostgresAuditSink
from keystone.audit.store import load_events, snapshot_head
from keystone.audit.verify import verify_chain
from keystone.authz.evaluator import OpaHttpEvaluator
from keystone.authz.service import AuthorizationService
from keystone.broker.issuance import IssuanceState
from keystone.broker.service import IssuanceService
from keystone.db.ids import uuid7
from keystone.db.redis import make_redis
from keystone.identity.jwks import JwksCache
from keystone.identity.oidc import GitHubOidcVerifier
from keystone.identity.replay import RedisReplayStore
from keystone.registry.repo import RoleRegistry
from tests.integration.test_authorization_opa import REVISION, opa_server  # noqa: F401
from tests.integration.test_issuance_service_pg import ARN, TEMPLATE, FakeConnector
from tests.integration.test_oidc_forgery_suite import (
    AUDIENCE,
    ISSUER,
    FakeOrigin,
    KeyPair,
    good_claims,
    sign,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH"),
]

SECRET = "never-stored"  # FakeConnector's secret_access_key


def _now_ms() -> int:
    return int(time.time() * 1000)


def _seed(engine: Engine, *, pin: bool = True) -> None:
    with engine.begin() as conn:
        registry = RoleRegistry(conn)
        role = registry.register_role(name="deploy-prod", role_arn=ARN, max_ttl_seconds=1800)
        registry.add_template(role_id=role.id, ref="s3-deploy-narrow", policy_document=TEMPLATE)
        if pin:
            conn.execute(
                text(
                    "INSERT INTO policy_pins (id, bundle_digest, bundle_sequence, active) "
                    "VALUES (:id, :digest, 1, true)"
                ),
                {"id": uuid7(), "digest": REVISION},
            )


class Stack:
    def __init__(
        self,
        engine: Engine,
        client_redis: redis.Redis,
        opa_url: str,
        *,
        identity_policy: BucketPolicy | None = None,
    ) -> None:
        self.pair = KeyPair("kid-1")
        self.connector = FakeConnector()
        sink = PostgresAuditSink()
        buckets = TokenBuckets(client_redis, _now_ms)
        limiter = (
            Tier1Limiter(buckets, identity_policy=identity_policy)
            if identity_policy
            else Tier1Limiter(buckets)
        )
        pipeline = CredentialPipeline(
            shedder=Tier0Shedder(buckets),
            verifier=GitHubOidcVerifier(
                issuer=ISSUER,
                audience=AUDIENCE,
                jwks=JwksCache(client_redis, FakeOrigin(self.pair), sleep=lambda _: None),
                replay=RedisReplayStore(client_redis),
            ),
            limiter=limiter,
            authorizer=AuthorizationService(
                engine, sink, OpaHttpEvaluator(opa_url), keystone_version="0.1.0"
            ),
            sts_slots=StsInflightGuard(client_redis),
            issuer=IssuanceService(engine, sink, self.connector),
            aggregator=FailureAggregator(client_redis),
            region_hint="eu-west-1",
        )
        self.client = TestClient(create_app(pipeline), raise_server_exceptions=False)

    def token(self, pair: KeyPair | None = None, **overrides: Any) -> str:
        return sign(pair or self.pair, good_claims(datetime.now(UTC), **overrides))

    def post(self, token: str, grant: str = "deploy-prod", ttl: int | None = 900) -> Any:
        body: dict[str, Any] = {"token": token, "grant": grant}
        if ttl is not None:
            body["ttl_seconds"] = ttl
        return self.client.post("/v1/credentials", json=body)


@pytest.fixture
def stack(app_engine: Engine, redis_client: redis.Redis, opa_server: str) -> Stack:  # noqa: F811
    _seed(app_engine)
    return Stack(app_engine, redis_client, opa_server)


def _chain(engine: Engine) -> list[Any]:
    with engine.connect() as conn:
        head = snapshot_head(conn)
        events = load_events(conn, 1, head.seq)
        assert verify_chain(events, expected_head=head).ok
    return events


def _issuance_states(engine: Engine) -> list[str]:
    with engine.connect() as conn:
        return [str(r.state) for r in conn.execute(text("SELECT state FROM issuances"))]


def test_golden_path_issues_once_and_marks_delivered(stack: Stack, app_engine: Engine) -> None:
    response = stack.post(stack.token())
    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["grant"] == "deploy-prod" and body["granted_ttl_seconds"] == 900
    assert body["credentials"]["secret_access_key"] == SECRET
    assert body["region_hint"] == "eu-west-1"

    events = _chain(app_engine)
    assert [e.event_type for e in events] == [
        EventType.DECISION_ALLOWED.value,
        EventType.CREDENTIAL_ISSUED.value,
    ]
    assert body["audit_seq"] == events[1].seq
    assert events[0].details["data"]["decision_id"] == body["decision_id"]
    # The response was the only place the secret existed (Ch. 24 cardinal invariant).
    assert all(SECRET not in e.canonical_payload.decode() for e in events)
    with app_engine.connect() as conn:
        dumped = conn.execute(text("SELECT row_to_json(i)::text FROM issuances i")).scalar_one()
    assert SECRET not in dumped
    # The background task ran after the body was sent.
    assert _issuance_states(app_engine) == [IssuanceState.DELIVERED.value]
    mint = stack.connector.requests[0]
    assert mint.role_arn == ARN and mint.duration_seconds == 900
    assert mint.tags["keystone:decision_id"] == body["decision_id"]


def test_replayed_token_is_409_and_mints_nothing(
    stack: Stack, app_engine: Engine, redis_client: redis.Redis
) -> None:
    token = stack.token()
    assert stack.post(token).status_code == 201
    replay = stack.post(token)
    assert replay.status_code == 409 and replay.json()["error"]["code"] == "TOKEN_REPLAYED"
    assert len(stack.connector.requests) == 1
    assert redis_client.keys("agg:token_replayed:*")  # counted, not chained per request (R4)


@pytest.mark.parametrize(
    "make_token",
    [
        lambda s: s.token(pair=KeyPair("kid-1")),  # right kid, wrong key
        lambda s: s.token(aud="someone-else"),
        lambda s: s.token(exp=int(time.time()) - 3600),
        lambda s: s.token(repository=None),  # required claim absent
    ],
)
def test_pre_auth_failures_are_a_uniform_401(
    stack: Stack,
    app_engine: Engine,
    redis_client: redis.Redis,
    make_token: Callable[[Stack], str],
) -> None:
    response = stack.post(make_token(stack))
    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == "TOKEN_INVALID" and error["message"] == "token rejected"
    assert stack.connector.requests == []
    assert redis_client.keys("agg:auth_failed:*")
    with app_engine.connect() as conn:
        assert snapshot_head(conn).seq == 0  # nothing chained per failed request


def test_policy_denial_is_403_audited_and_mints_nothing(stack: Stack, app_engine: Engine) -> None:
    response = stack.post(stack.token(repository="acme/other"))
    assert response.status_code == 403
    body = response.json()
    assert body["error"]["code"] == "POLICY_DENIED"
    assert body["error"]["reasons"] == ["NO_GRANT_MATCHED"]
    assert body["error"]["policy_digest"] == REVISION
    events = _chain(app_engine)
    assert [e.event_type for e in events] == [EventType.DECISION_DENIED.value]
    assert events[0].details["data"]["decision_id"] == body["decision_id"]
    assert stack.connector.requests == [] and _issuance_states(app_engine) == []


def test_identity_rate_limit_is_429_with_retry_after(
    app_engine: Engine,
    redis_client: redis.Redis,
    opa_server: str,  # noqa: F811
) -> None:
    _seed(app_engine)
    stack = Stack(
        app_engine,
        redis_client,
        opa_server,
        identity_policy=BucketPolicy(limit=1, window_seconds=300, burst=1),
    )
    assert stack.post(stack.token()).status_code == 201
    limited = stack.post(stack.token())
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMITED_IDENTITY"
    assert int(limited.headers["retry-after"]) >= 1
    assert len(stack.connector.requests) == 1


def test_no_active_pin_fails_closed(
    app_engine: Engine,
    redis_client: redis.Redis,
    opa_server: str,  # noqa: F811
) -> None:
    _seed(app_engine, pin=False)
    stack = Stack(app_engine, redis_client, opa_server)
    response = stack.post(stack.token())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "POLICY_PIN_MISSING"
    assert stack.connector.requests == []


def test_redis_down_fails_closed(
    app_engine: Engine,
    redis_client: redis.Redis,
    opa_server: str,  # noqa: F811
) -> None:
    _seed(app_engine)
    dead = make_redis("redis://127.0.0.1:1/0")
    stack = Stack(app_engine, dead, opa_server)
    response = stack.post(stack.token())
    assert response.status_code == 503
    error = response.json()["error"]
    assert error["code"] == "KEYSTONE_DEPENDENCY_UNAVAILABLE" and error["retryable"] is True
    assert stack.connector.requests == []


def test_unregistered_grant_allowed_by_policy_is_a_registry_divergence(
    app_engine: Engine,
    redis_client: redis.Redis,
    opa_server: str,  # noqa: F811
) -> None:
    _seed(app_engine)
    with app_engine.begin() as conn:
        RoleRegistry(conn).set_role_enabled("deploy-prod", False)
    stack = Stack(app_engine, redis_client, opa_server)
    response = stack.post(stack.token())
    assert response.status_code == 500
    error = response.json()["error"]
    assert error["code"] == "POLICY_REGISTRY_DIVERGENCE"
    assert error["details"] == {"reason": "REGISTRY_ROLE_DISABLED"}
    events = _chain(app_engine)
    assert [e.event_type for e in events] == [
        EventType.DECISION_ALLOWED.value,
        EventType.CREDENTIAL_ISSUE_FAILED.value,
    ]
    assert stack.connector.requests == []


def test_request_ids_are_unique_per_response(stack: Stack) -> None:
    ids = {stack.client.get("/healthz").headers["x-request-id"] for _ in range(3)}
    assert len(ids) == 3 and all(uuid.UUID(i) for i in ids)
