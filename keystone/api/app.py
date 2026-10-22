"""Public-plane HTTP surface (Ch. 39-43) and the composition root (Ch. 54).

Transport rules live here and nowhere else: 32 KiB body cap, `application/json` only, strict
UTF-8, duplicate JSON keys and non-finite numbers refused, `request_id` and
`Cache-Control: no-store` on every response. The 201 body is the only place a credential ever
exists; DELIVERED is marked in a background task that runs after the body is sent (an unsent
response leaves ISSUED for the reconciler, Ch. 24).

Run: `uvicorn --factory keystone.api.app:app_from_env` with the KEYSTONE_* settings.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import JsonValue, ValidationError
from sqlalchemy import create_engine
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from keystone.api.credentials import CredentialHandler, CredentialPipeline, CredentialRequest
from keystone.api.errors import KNOWN_ERRORS, ApiError, envelope, map_exception, rejected
from keystone.api.ratelimit import StsInflightGuard, Tier0Shedder, Tier1Limiter, TokenBuckets
from keystone.audit.aggregation import FailureAggregator
from keystone.audit.sink import PostgresAuditSink
from keystone.authz.evaluator import OpaHttpEvaluator
from keystone.authz.service import AuthorizationService, Denied
from keystone.broker.connectors.aws_sts import AwsStsConnector
from keystone.broker.service import IssuanceService
from keystone.config.settings import Settings
from keystone.db.ids import uuid7
from keystone.db.redis import make_redis
from keystone.identity.jwks import HttpJwksSource, JwksCache
from keystone.identity.oidc import GitHubOidcVerifier
from keystone.identity.replay import RedisReplayStore

MAX_BODY_BYTES = 32 * 1024
_log = logging.getLogger("keystone.api")


def _json_response(
    status: int,
    content: dict[str, JsonValue],
    *,
    headers: dict[str, str] | None = None,
    background: BackgroundTask | None = None,
) -> JSONResponse:
    return JSONResponse(status_code=status, content=content, headers=headers, background=background)


def _error_response(error: ApiError, request_id: str) -> JSONResponse:
    headers = None
    if error.retry_after_seconds is not None:
        headers = {"Retry-After": str(error.retry_after_seconds)}
    return _json_response(error.status, envelope(error, request_id), headers=headers)


def _content_type_ok(value: str) -> bool:
    media, _, params = value.partition(";")
    if media.strip().lower() != "application/json":
        return False
    for param in filter(None, (p.strip() for p in params.split(";"))):
        name, _, val = param.partition("=")
        if name.strip().lower() != "charset" or val.strip().strip('"').lower() != "utf-8":
            return False
    return True


async def _read_body(request: Request) -> bytes:
    if not _content_type_ok(request.headers.get("content-type", "")):
        raise rejected(415, "VALIDATION_CONTENT_TYPE", "content type must be application/json")
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES):
        raise rejected(413, "VALIDATION_BODY_TOO_LARGE", "request body exceeds 32 KiB")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise rejected(413, "VALIDATION_BODY_TOO_LARGE", "request body exceeds 32 KiB")
    return bytes(body)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _refuse_constant(_: str) -> Any:
    raise ValueError("non-finite number")


def _parse(body: bytes) -> CredentialRequest:
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise rejected(400, "VALIDATION_ENCODING", "request body must be UTF-8") from exc
    try:
        raw = json.loads(
            text, object_pairs_hook=_no_duplicate_keys, parse_constant=_refuse_constant
        )
    except ValueError as exc:
        raise rejected(400, "VALIDATION_MALFORMED_JSON", "request body is not valid JSON") from exc
    try:
        return CredentialRequest.model_validate(raw)
    except ValidationError as exc:
        # Field locations and error kinds only: hostile input is never echoed back.
        problems: list[JsonValue] = [
            {"field": ".".join(str(p) for p in e["loc"]) or "$", "error": e["type"]}
            for e in exc.errors()
        ]
        raise rejected(
            400, "VALIDATION_FAILED", "request failed validation", problems=problems
        ) from exc


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
    return _json_response(403, {"decision_id": str(denied.decision_id), "error": error})


def create_app(pipeline: CredentialHandler) -> FastAPI:
    # The OpenAPI schema is a build artifact (Ch. 39), not something the public plane serves.
    app = FastAPI(title="Keystone", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.request_id = str(uuid7())
        response = await call_next(request)
        response.headers["X-Request-Id"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}.get(exc.status_code, "HTTP_ERROR")
        error = ApiError(exc.status_code, code, "no such route or method", False)
        return _error_response(error, request.state.request_id)

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Runs outside the middleware stack, so it sets the per-response headers itself.
        request_id = getattr(request.state, "request_id", "unknown")
        _log.error("unexpected failure", exc_info=exc, extra={"request_id": request_id})
        error = ApiError(500, "KEYSTONE_INTERNAL_ERROR", "internal error", False)
        response = _error_response(error, request_id)
        response.headers["X-Request-Id"] = request_id
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        # Liveness only (Ch. 53): no dependency probes here; those belong to /readyz.
        return {"status": "ok"}

    @app.post("/v1/credentials")
    async def credentials(request: Request) -> Response:
        request_id: str = request.state.request_id
        try:
            payload = _parse(await _read_body(request))
            source_ip = request.client.host if request.client else "unknown"
            outcome = await run_in_threadpool(
                pipeline.handle, payload, source_ip=source_ip, request_id=request_id
            )
        except KNOWN_ERRORS as exc:
            return _error_response(map_exception(exc), request_id)
        if isinstance(outcome, Denied):
            return _denied(outcome, request_id)
        return _json_response(
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
        limiter=Tier1Limiter(buckets),
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
        region_hint=settings.aws_region,
    )


def app_from_env() -> FastAPI:
    return create_app(build_pipeline(Settings.from_env(os.environ)))
