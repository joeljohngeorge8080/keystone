"""Integration fixtures: a real PostgreSQL (Docker) migrated from scratch for every test."""

import os
from collections.abc import Iterator
from datetime import date

import pytest
import redis
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from keystone.db.partitions import ensure_audit_partition
from keystone.db.redis import make_redis

DATABASE_URL_ENV = "KEYSTONE_TEST_DATABASE_URL"
REDIS_URL_ENV = "KEYSTONE_TEST_REDIS_URL"
APP_LOGIN_ROLE = "keystone_app_login"
APP_LOGIN_PASSWORD = "app-test-only"  # throwaway local test credential
PINNED_TEST_MONTH = date(2026, 9, 1)  # every fixed test clock is in this month


def _admin_url() -> str:
    url = os.environ.get(DATABASE_URL_ENV)
    if not url:
        pytest.skip(f"{DATABASE_URL_ENV} not set; start deploy/compose.test.yml")
    return url


def _migrate(url: str) -> None:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")


@pytest.fixture
def admin_engine() -> Iterator[Engine]:
    url = _admin_url()
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
    _migrate(url)
    with engine.begin() as connection:
        # Migration 0001 seeds partitions from the month it runs in; tests pin their clocks to
        # PINNED_TEST_MONTH, which falls outside that window once the calendar moves past it.
        ensure_audit_partition(connection, PINNED_TEST_MONTH)
        connection.execute(
            text(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
                f"'{APP_LOGIN_ROLE}') THEN CREATE ROLE {APP_LOGIN_ROLE} LOGIN PASSWORD "
                f"'{APP_LOGIN_PASSWORD}' IN ROLE keystone_app; END IF; END $$"
            )
        )
    yield engine
    engine.dispose()


@pytest.fixture
def app_engine(admin_engine: Engine) -> Iterator[Engine]:
    """Connects as the least-privilege application role the service will really run as."""
    url = admin_engine.url.set(username=APP_LOGIN_ROLE, password=APP_LOGIN_PASSWORD)
    engine = create_engine(url)
    yield engine
    engine.dispose()


@pytest.fixture
def redis_client() -> Iterator[redis.Redis]:
    url = os.environ.get(REDIS_URL_ENV)
    if not url:
        pytest.skip(f"{REDIS_URL_ENV} not set; start deploy/compose.test.yml")
    client = make_redis(url, timeout_seconds=1.0)
    client.flushdb()
    yield client
    client.flushdb()
    client.close()
