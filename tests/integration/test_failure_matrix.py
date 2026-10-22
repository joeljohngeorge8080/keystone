"""Ch. 27 failure table as one matrix: every dependency outage against the issuance path.

Fail-closed doctrine: no dependency failure may produce an unverified, un-policied, unaudited or
un-rate-limited issuance. Each row names the dependency, how it is broken, and what the public
plane must answer. Every 503 carries `Retry-After` and a stable code (Ch. 27), nothing is minted
on a deny-all row, and the audit chain still verifies afterwards (Ch. 59) wherever PostgreSQL is up.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
import redis
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from keystone.audit.events import EventType
from keystone.audit.store import snapshot_head
from keystone.broker.connectors.base import UnavailableError
from keystone.db.redis import make_redis
from tests.integration.test_authorization_opa import opa_server  # noqa: F401
from tests.integration.test_credentials_api import Stack, _chain, _issuance_states, _seed
from tests.integration.test_issuance_service_pg import FakeConnector

pytestmark = pytest.mark.integration

DEAD_PG = "postgresql+psycopg://keystone_app:unused@127.0.0.1:1/none"
DEAD_REDIS = "redis://127.0.0.1:1/0"
DEAD_OPA = "http://127.0.0.1:1"


@dataclass(frozen=True)
class Env:
    engine: Engine
    redis: redis.Redis
    opa_url: str


@dataclass(frozen=True)
class Row:
    dependency: str
    build: Callable[[Env], Stack]
    status: int
    code: str | None  # None on a success row
    minted: bool
    chain: tuple[str, ...] | None  # event types after the request; None when PG is the outage


def _opa_down(env: Env) -> Stack:
    return Stack(env.engine, env.redis, DEAD_OPA)


def _postgres_down(env: Env) -> Stack:
    dead = create_engine(DEAD_PG, connect_args={"connect_timeout": 1})
    return Stack(dead, env.redis, env.opa_url)


def _redis_down(env: Env) -> Stack:
    return Stack(env.engine, make_redis(DEAD_REDIS), env.opa_url)


def _sts_down(env: Env) -> Stack:
    return Stack(
        env.engine, env.redis, env.opa_url, connector=FakeConnector(UnavailableError("throttled"))
    )


def _jwks_down_cold(env: Env) -> Stack:
    stack = Stack(env.engine, env.redis, env.opa_url)
    stack.origin.fail = True
    return stack


def _worker_down(env: Env) -> Stack:
    # No Celery worker exists in this process at all: the issuance path must not need one.
    return Stack(env.engine, env.redis, env.opa_url)


def _anchor_store_down(env: Env) -> Stack:
    stack = Stack(env.engine, env.redis, env.opa_url)
    stack.breaker.record_failure(datetime.now(UTC) - timedelta(minutes=11))
    return stack


DEPENDENCY = "KEYSTONE_DEPENDENCY_UNAVAILABLE"
ALLOWED = EventType.DECISION_ALLOWED.value
ISSUED = EventType.CREDENTIAL_ISSUED.value
FAILED = EventType.CREDENTIAL_ISSUE_FAILED.value

MATRIX = [
    Row("opa", _opa_down, 503, DEPENDENCY, minted=False, chain=()),
    Row("postgres", _postgres_down, 503, DEPENDENCY, minted=False, chain=None),
    Row("redis", _redis_down, 503, DEPENDENCY, minted=False, chain=()),
    Row("aws-sts", _sts_down, 503, "STS_UNAVAILABLE", minted=False, chain=(ALLOWED, FAILED)),
    Row("jwks-cold", _jwks_down_cold, 503, DEPENDENCY, minted=False, chain=()),
    Row("celery-worker", _worker_down, 201, None, minted=True, chain=(ALLOWED, ISSUED)),
    Row(
        "anchor-store",
        _anchor_store_down,
        503,
        "AUDIT_ANCHOR_STORE_UNREACHABLE",
        minted=False,
        chain=(),
    ),
]


@pytest.mark.parametrize("row", MATRIX, ids=[r.dependency for r in MATRIX])
def test_failure_matrix(
    row: Row,
    app_engine: Engine,
    redis_client: redis.Redis,
    opa_server: str,  # noqa: F811
) -> None:
    _seed(app_engine)
    stack = row.build(Env(app_engine, redis_client, opa_server))
    response = stack.post(stack.token())

    assert response.status_code == row.status, response.text
    if row.code is not None:
        error = response.json()["error"]
        assert error["code"] == row.code
        assert error["retryable"] is (row.status == 503)
    if row.status == 503:
        assert int(response.headers["retry-after"]) >= 1, "every 503 carries Retry-After"
        assert "Traceback" not in response.text and "127.0.0.1" not in response.text
    # A mint is attempted only on the allow path; nothing is delivered on a deny-all row.
    minted = bool(stack.connector.requests) and stack.connector.outcome is None
    assert minted is row.minted
    if row.chain is not None:
        assert tuple(e.event_type for e in _chain(app_engine)) == row.chain
    if row.dependency == "aws-sts":
        assert _issuance_states(app_engine) == ["failed"]


def test_jwks_origin_down_with_a_warm_cache_still_issues(
    app_engine: Engine,
    redis_client: redis.Redis,
    opa_server: str,  # noqa: F811
) -> None:
    """Ch. 27: GitHub JWKS down with a warm cache (<= 6 h) => normal issuance, served stale."""
    _seed(app_engine)
    warm = Stack(app_engine, redis_client, opa_server)
    assert warm.post(warm.token()).status_code == 201
    redis_client.set("jwks:fresh_until", b"0")  # the 15 min fresh window has lapsed
    cold_process = Stack(app_engine, redis_client, opa_server)
    cold_process.pair = warm.pair
    cold_process.origin.fail = True
    response = cold_process.post(cold_process.token())
    assert response.status_code == 201, response.text
    assert cold_process.origin.fetches == 1  # origin was tried, then the stale copy served


def test_jwks_beyond_the_stale_ceiling_fails_closed(
    app_engine: Engine,
    redis_client: redis.Redis,
    opa_server: str,  # noqa: F811
) -> None:
    """Past the 6 h ceiling the cached document has expired out of Redis: 503, nothing minted."""
    _seed(app_engine)
    warm = Stack(app_engine, redis_client, opa_server)
    assert warm.post(warm.token()).status_code == 201
    redis_client.delete("jwks:raw", "jwks:fresh_until")  # what the 6 h Redis TTL does
    later = Stack(app_engine, redis_client, opa_server)
    later.pair = warm.pair
    later.origin.fail = True
    response = later.post(later.token())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == DEPENDENCY
    assert int(response.headers["retry-after"]) >= 1
    assert len(later.connector.requests) == 0


def test_postgres_down_mid_matrix_leaves_no_partial_chain(
    app_engine: Engine,
    redis_client: redis.Redis,
    opa_server: str,  # noqa: F811
) -> None:
    """After the PostgreSQL row, the real database holds no decision and no issuance."""
    _seed(app_engine)
    stack = _postgres_down(Env(app_engine, redis_client, opa_server))
    assert stack.post(stack.token()).status_code == 503
    with app_engine.connect() as conn:
        assert snapshot_head(conn).seq == 0
        assert conn.execute(text("SELECT count(*) FROM issuances")).scalar_one() == 0
