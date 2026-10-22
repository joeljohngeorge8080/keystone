"""Performance tests reuse the integration fixtures (real PostgreSQL and Redis)."""

from tests.integration.conftest import admin_engine, app_engine, redis_client  # noqa: F401
