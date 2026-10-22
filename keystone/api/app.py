"""Public-plane HTTP surface (Ch. 39-43) and the composition root (Ch. 54).

Transport rules (32 KiB body cap, `application/json` only, strict UTF-8, duplicate JSON keys and
non-finite numbers refused, `request_id` and `Cache-Control: no-store` on every response) come
from `keystone.api.http`, shared with the admin plane. The 201 body is the only place a
credential ever exists; DELIVERED is marked in a background task that runs after the body is
sent (an unsent response leaves ISSUED for the reconciler, Ch. 24).

Run: `uvicorn --factory keystone.api.app:app_from_env` with the KEYSTONE_* settings.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Sequence
from datetime import timedelta

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import JsonValue
from sqlalchemy import create_engine
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from keystone.api.credentials import CredentialHandler, CredentialPipeline, CredentialRequest
from keystone.api.errors import KNOWN_ERRORS, map_exception
from keystone.api.http import (
    Network,
    client_ip,
    error_response,
    install_common,
    json_response,
    parse_networks,
    read_json,
)
from keystone.api.ratelimit import StsInflightGuard, Tier0Shedder, Tier1Limiter, TokenBuckets
from keystone.audit.aggregation import FailureAggregator
from keystone.audit.anchor import AnchorBreaker
from keystone.audit.sink import PostgresAuditSink
from keystone.authz.evaluator import OpaHttpEvaluator
from keystone.authz.service import AuthorizationService, Denied
from keystone.broker.connectors.aws_sts import AwsStsConnector
from keystone.broker.service import IssuanceService
from keystone.config.settings import Settings
from keystone.db.redis import make_redis
from keystone.identity.jwks import HttpJwksSource, JwksCache
from keystone.identity.oidc import GitHubOidcVerifier
from keystone.identity.replay import RedisReplayStore
from keystone.registry.repo import RateLimitOverrides
from keystone.telemetry.logs import configure_logging

MAX_BODY_BYTES = 32 * 1024
_log = logging.getLogger("keystone.api")


def _denied(denied: Denied, request_id: str) -> JSONResponse:
    # Ch. 42 denial body: the envelope's fields plus the decision's explanation.
    error: dict[str, JsonValue] = {
        "code": "POLICY_DENIED",
        "message": "policy denied the request",
        "request_id": request_id,
        "retryable": False,
        "reasons": list(denied.reasons),
        "rule_path": denied.rule_path,
        "policy_digest": denied.policy_digest,
    }
    return json_response(403, {"decision_id": str(denied.decision_id), "error": error})


def create_app(pipeline: CredentialHandler, *, trusted_proxies: Sequence[Network] = ()) -> FastAPI:
    # The OpenAPI schema is a build artifact (Ch. 39), not something the public plane serves.
    app = FastAPI(title="Keystone", docs_url=None, redoc_url=None, openapi_url=None)
    install_common(app, _log)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        # Liveness only (Ch. 53): no dependency probes here; those belong to /readyz.
        return {"status": "ok"}

    @app.post("/v1/credentials")
    async def credentials(request: Request) -> Response:
        request_id: str = request.state.request_id
        try:
            payload = await read_json(request, CredentialRequest, max_bytes=MAX_BODY_BYTES)
            source_ip = client_ip(request, trusted_proxies)
            outcome = await run_in_threadpool(
                pipeline.handle, payload, source_ip=source_ip, request_id=request_id
            )
        except KNOWN_ERRORS as exc:
            return error_response(map_exception(exc), request_id)
        if isinstance(outcome, Denied):
            return _denied(outcome, request_id)
        return json_response(
            201,
            outcome.response.model_dump(mode="json"),
            background=BackgroundTask(pipeline.mark_delivered, outcome.issuance_id),
        )

    return app


def build_pipeline(settings: Settings) -> CredentialPipeline:
    """The single composition root: every service is a constructor-injected singleton."""
    engine = create_engine(settings.database_url, pool_pre_ping=True)
    primary = make_redis(settings.redis_url)
    sink = PostgresAuditSink()
    buckets = TokenBuckets(primary, lambda: int(time.time() * 1000))
    return CredentialPipeline(
        shedder=Tier0Shedder(buckets),
        verifier=GitHubOidcVerifier(
            issuer=settings.oidc_issuer,
            audience=settings.oidc_audience,
            jwks=JwksCache(primary, HttpJwksSource(settings.jwks_url)),
            replay=RedisReplayStore(primary),
        ),
        limiter=Tier1Limiter(buckets, overrides=RateLimitOverrides(engine)),
        authorizer=AuthorizationService(
            engine,
            sink,
            OpaHttpEvaluator(settings.opa_url),
            keystone_version=settings.keystone_version,
        ),
        sts_slots=StsInflightGuard(primary),
        issuer=IssuanceService(
            engine,
            sink,
            AwsStsConnector(
                region=settings.aws_region,
                endpoint_url=settings.sts_endpoint_url,
                connect_timeout=settings.sts_connect_timeout_seconds,
                read_timeout=settings.sts_read_timeout_seconds,
            ),
        ),
        aggregator=FailureAggregator(make_redis(settings.effective_aggregation_redis_url)),
        breaker=AnchorBreaker(
            primary, threshold=timedelta(seconds=settings.anchor_breaker_threshold_seconds)
        ),
        region_hint=settings.aws_region,
    )


def app_from_env() -> FastAPI:
    configure_logging("public")
    settings = Settings.from_env(os.environ)
    return create_app(
        build_pipeline(settings), trusted_proxies=parse_networks(settings.trusted_proxies)
    )
