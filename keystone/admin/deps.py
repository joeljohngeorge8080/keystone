"""What every admin route depends on: the service container and bearer authentication.

Module level on purpose: with postponed annotations FastAPI resolves `Admin` via module globals.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.engine import Engine

from keystone.admin.readiness import ReadinessProbe
from keystone.admin.tokens import AdminAuthFailed, AdminPrincipal, AdminTokenService
from keystone.authz.pins import BundleGateway, PinActivator, StagedBundleStore
from keystone.broker.revocation import RevocationService
from keystone.registry.admin import Actor, RegistryAdmin


@dataclass(frozen=True, slots=True)
class AdminServices:
    engine: Engine
    tokens: AdminTokenService
    readiness: ReadinessProbe
    pins: PinActivator
    gateway: BundleGateway
    bundles: StagedBundleStore
    bundle_service_token: str | None
    registry: RegistryAdmin
    revocations: RevocationService


def bearer(request: Request) -> str | None:
    scheme, _, credential = request.headers.get("authorization", "").partition(" ")
    credential = credential.strip()
    return credential if scheme.lower() == "bearer" and credential else None


def services_of(request: Request) -> AdminServices:
    services: AdminServices = request.app.state.services
    return services


def require_admin(request: Request) -> AdminPrincipal:
    token = bearer(request)
    if token is None:
        raise AdminAuthFailed("missing bearer token")
    return services_of(request).tokens.authenticate(token)


def actor_of(principal: AdminPrincipal) -> Actor:
    return Actor(name=principal.name, admin_principal_id=principal.id)


Admin = Annotated[AdminPrincipal, Depends(require_admin)]
Services = Annotated[AdminServices, Depends(services_of)]
