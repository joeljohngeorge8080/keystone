"""Admin plane (Ch. 39/40/53, TB6): a separate app bound to a non-public listener.

Every route except `/readyz` and the bundle route requires `Authorization: Bearer <admin token>`
(hash-stored, Ch. 48). Every mutation is chained in the audit log with the acting principal.
The bundle route serves the staged policy bundle to the OPA sidecar (R5 load phase) and accepts
only the dedicated bundle-service bearer, compared in constant time.

Run: `uvicorn --factory keystone.admin.app:admin_app_from_env --host <private interface>`.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import uuid
from datetime import UTC, timedelta
from typing import Annotated

import boto3
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, JsonValue
from sqlalchemy import create_engine
from starlette.concurrency import run_in_threadpool

from keystone.admin import audit_routes, registry_routes
from keystone.admin.deps import Admin, AdminServices, bearer
from keystone.admin.readiness import ReadinessProbe
from keystone.admin.tokens import (
    PRINCIPAL_PATTERN,
    AdminAuthFailed,
    AdminTokenRecord,
    AdminTokenService,
)
from keystone.api.errors import ApiError
from keystone.api.http import (
    error_response,
    install_common,
    json_response,
    read_body,
    read_json,
    request_id_of,
)
from keystone.audit.anchor import AnchorBreaker
from keystone.audit.sink import PostgresAuditSink
from keystone.authz.pins import (
    OpaBundleGateway,
    PinActivator,
    PolicyPinRepository,
    StagedBundleStore,
    restage_active_bundle,
)
from keystone.authz.service import active_pin
from keystone.broker.connectors.aws_sts import AwsStsConnector
from keystone.broker.revocation import IamDenyPolicyApplier, RevocationService
from keystone.config.settings import Settings
from keystone.db.redis import make_redis
from keystone.identity.jwks import HttpJwksSource, JwksCache
from keystone.registry.admin import RegistryAdmin
from keystone.registry.repo import RegistryCode, RegistryError
from keystone.telemetry.clock import clock_sync_state
from keystone.telemetry.logs import configure_logging

MAX_JSON_BYTES = 32 * 1024
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
BUNDLE_PATH = "/bundles/keystone.tar.gz"
_log = logging.getLogger("keystone.admin")


class IssueTokenRequest(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    principal: str = Field(pattern=PRINCIPAL_PATTERN)
    ttl_days: int = Field(default=30, ge=1, le=90)


def _token_json(record: AdminTokenRecord) -> dict[str, JsonValue]:
    return {
        "id": str(record.id),
        "principal": record.principal,
        "created_at": record.created_at.astimezone(UTC).isoformat(),
        "expires_at": record.expires_at.astimezone(UTC).isoformat(),
        "revoked_at": record.revoked_at.astimezone(UTC).isoformat() if record.revoked_at else None,
    }


# On the admin plane an unknown role/template is a plain 404 and a disabled one a 409; the
# public plane maps the same exception to 500 POLICY_REGISTRY_DIVERGENCE (Ch. 19).
_REGISTRY_STATUS = {
    RegistryCode.ROLE_UNKNOWN: 404,
    RegistryCode.TEMPLATE_UNKNOWN: 404,
    RegistryCode.ROLE_DISABLED: 409,
    RegistryCode.TEMPLATE_DISABLED: 409,
}


def create_admin_app(services: AdminServices) -> FastAPI:
    app = FastAPI(title="Keystone admin", docs_url=None, redoc_url=None, openapi_url=None)
    install_common(app, _log, map_known_errors=True)
    app.state.services = services
    app.include_router(registry_routes.router)
    app.include_router(audit_routes.router)

    async def registry_error(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, RegistryError)
        error = ApiError(_REGISTRY_STATUS[exc.code], exc.code.value, str(exc), False)
        return error_response(error, request_id_of(request))

    app.add_exception_handler(RegistryError, registry_error)

    @app.get("/readyz")
    def readyz() -> JSONResponse:
        result = services.readiness.check()
        body: dict[str, JsonValue] = {
            "ready": result.ready,
            "checks": dict(result.checks),
            "degraded": list(result.degraded),
        }
        return json_response(200 if result.ready else 503, body)

    # ---- admin tokens (Ch. 40 /v1/admin/tokens) ----

    @app.get("/v1/admin/tokens")
    def list_tokens(_: Admin) -> dict[str, JsonValue]:
        return {"tokens": [_token_json(r) for r in services.tokens.list()]}

    @app.post("/v1/admin/tokens")
    async def issue_token(request: Request, principal: Admin) -> JSONResponse:
        body = await read_json(request, IssueTokenRequest, max_bytes=MAX_JSON_BYTES)
        issued = await run_in_threadpool(
            services.tokens.issue,
            principal_name=body.principal,
            ttl=timedelta(days=body.ttl_days),
            issued_by=principal,
        )
        # The only time the plaintext exists outside the caller: this response (no-store).
        content = {**_token_json(issued.record), "token": issued.token}
        return json_response(201, {**content, "audit_seq": issued.audit_seq})

    @app.delete("/v1/admin/tokens/{token_id}")
    def revoke_token(token_id: uuid.UUID, principal: Admin) -> dict[str, JsonValue]:
        return _token_json(services.tokens.revoke(token_id, revoked_by=principal))

    # ---- policy (Ch. 40 /v1/policy/*, R5/R8) ----

    @app.get("/v1/policy/pins")
    def pin_history(
        _: Admin, limit: Annotated[int, Query(ge=1, le=200)] = 50
    ) -> dict[str, JsonValue]:
        with services.engine.connect() as conn:
            records = PolicyPinRepository(conn).history(limit)
        return {
            "pins": [
                {
                    "id": str(r.id),
                    "bundle_digest": r.bundle_digest,
                    "bundle_sequence": r.bundle_sequence,
                    "active": r.active,
                    "forced_rollback": r.forced_rollback,
                    "pinned_at": r.pinned_at.astimezone(UTC).isoformat(),
                    "pinned_by": r.pinned_by,
                }
                for r in records
            ]
        }

    @app.post("/v1/policy/pins")
    async def activate_pin(
        request: Request, principal: Admin, force_rollback: bool = False
    ) -> JSONResponse:
        bundle = await read_body(
            request, content_type="application/gzip", max_bytes=MAX_BUNDLE_BYTES
        )
        result = await run_in_threadpool(
            services.pins.activate,
            bundle,
            pinned_by=principal.id,
            actor=principal.name,
            force_rollback=force_rollback,
        )
        return json_response(
            201,
            {
                "pin_id": str(result.pin.id),
                "bundle_digest": result.pin.bundle_digest,
                "bundle_sequence": result.pin.bundle_sequence,
                "rolled_back": result.rolled_back,
                "audit_seq": result.audit_seq,
            },
        )

    @app.get("/v1/policy/status")
    def policy_status(_: Admin) -> dict[str, JsonValue]:
        with services.engine.connect() as conn:
            pin = active_pin(conn)
        loaded = services.gateway.loaded_digest()
        return {
            "active_pin": None
            if pin is None
            else {
                "id": str(pin.id),
                "bundle_digest": pin.bundle_digest,
                "bundle_sequence": pin.bundle_sequence,
            },
            "loaded_digest": loaded,
            "divergent": pin is not None and loaded != pin.bundle_digest,
        }

    # ---- bundle server for the OPA sidecar (R5 load phase) ----

    expected = services.bundle_service_token
    expected_digest = hashlib.sha256(expected.encode()).digest() if expected else None

    @app.get(BUNDLE_PATH)
    def serve_bundle(request: Request) -> Response:
        presented = bearer(request)
        if expected_digest is None or presented is None:
            raise AdminAuthFailed("bundle service token required")
        # Compare fixed-length digests so neither length nor content leaks through timing.
        if not hmac.compare_digest(hashlib.sha256(presented.encode()).digest(), expected_digest):
            raise AdminAuthFailed("bundle service token rejected")
        current = services.bundles.current()
        if current is None:
            error = ApiError(404, "BUNDLE_NOT_STAGED", "no policy bundle is staged", False)
            return error_response(error, request_id_of(request))
        digest, bundle = current
        return Response(bundle, media_type="application/gzip", headers={"ETag": f'"{digest}"'})

    return app


def build_admin(settings: Settings) -> AdminServices:
    """The admin plane's composition root."""
    engine = create_engine(settings.database_url, pool_pre_ping=True)
    primary = make_redis(settings.redis_url)
    sink = PostgresAuditSink()
    bundles = StagedBundleStore()
    gateway = OpaBundleGateway(bundles, settings.opa_url)
    breaker = AnchorBreaker(
        primary, threshold=timedelta(seconds=settings.anchor_breaker_threshold_seconds)
    )
    return AdminServices(
        engine=engine,
        tokens=AdminTokenService(engine, sink),
        readiness=ReadinessProbe(
            engine,
            primary,
            gateway,
            JwksCache(primary, HttpJwksSource(settings.jwks_url)),
            breaker,
            clock_sync=clock_sync_state if settings.clock_sync_check else None,
        ),
        pins=PinActivator(engine, sink, gateway),
        gateway=gateway,
        bundles=bundles,
        bundle_service_token=settings.bundle_service_token.get_secret_value()
        if settings.bundle_service_token
        else None,
        registry=RegistryAdmin(
            engine, sink, AwsStsConnector(region=settings.aws_region).validate_registration
        ),
        revocations=RevocationService(
            engine,
            sink,
            IamDenyPolicyApplier(
                boto3.client("iam", region_name=settings.aws_region),
                enabled=settings.revocation_put_role_policy_enabled,
            ),
        ),
    )


def admin_app_from_env() -> FastAPI:
    configure_logging("admin")
    settings = Settings.from_env(os.environ)
    services = build_admin(settings)
    if restage_active_bundle(services.engine, services.bundles) is None:
        _log.warning("no persisted bundle for the active pin; OPA polls 404 until the next pin")
    if settings.admin_bootstrap_token is not None:
        record = services.tokens.bootstrap(settings.admin_bootstrap_token.get_secret_value())
        if record is not None:
            _log.warning("admin bootstrap token registered; it expires %s", record.expires_at)
    return create_admin_app(services)
