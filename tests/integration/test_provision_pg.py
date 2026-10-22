"""Deployment provisioning (Ch. 62): migrate, partitions, a least-privilege service login role."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError

from keystone.config.settings import Settings, SettingsError
from keystone.db.provision import ProvisionError, ensure_login_role, provision

pytestmark = pytest.mark.integration

ROLE = "keystone_svc_test"
PASSWORD = "svc-" + "p" * 30


def _env(admin_engine: Engine, password_file: Path) -> dict[str, str]:
    return {
        "KEYSTONE_MIGRATION_DATABASE_URL": admin_engine.url.render_as_string(hide_password=False),
        "KEYSTONE_APP_DB_ROLE": ROLE,
        "KEYSTONE_APP_DB_PASSWORD_FILE": str(password_file),
    }


def test_provision_is_idempotent_and_the_role_is_least_privilege(
    admin_engine: Engine, tmp_path: Path
) -> None:
    secret = tmp_path / "pw"
    secret.write_text(PASSWORD + "\n")
    provision(_env(admin_engine, secret))
    provision(_env(admin_engine, secret))  # a re-deploy changes nothing but the password

    service = create_engine(admin_engine.url.set(username=ROLE, password=PASSWORD))
    try:
        with service.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 0
            assert (
                conn.execute(
                    text("SELECT keystone_ensure_audit_partition(date_trunc('month', now())::date)")
                ).scalar_one()
                is False
            )
        with pytest.raises(DBAPIError, match="permission denied"), service.begin() as conn:
            conn.execute(text("DELETE FROM audit_anchors"))
        with pytest.raises(DBAPIError, match="permission denied"), service.begin() as conn:
            conn.execute(text("CREATE TABLE x (id int)"))
    finally:
        service.dispose()


def test_rotating_the_password_takes_effect(admin_engine: Engine, tmp_path: Path) -> None:
    secret = tmp_path / "pw"
    secret.write_text(PASSWORD)
    provision(_env(admin_engine, secret))
    rotated = "rotated-" + "q" * 30
    secret.write_text(rotated)
    provision(_env(admin_engine, secret))
    old = create_engine(admin_engine.url.set(username=ROLE, password=PASSWORD))
    with pytest.raises(DBAPIError), old.connect():
        pass
    old.dispose()


@pytest.mark.parametrize(
    ("name", "password", "match"),
    [
        ("Keystone-Svc", PASSWORD, "plain lowercase"),
        ("x; DROP TABLE audit_events", PASSWORD, "plain lowercase"),
        ("keystone_app", PASSWORD, "plain lowercase"),  # never re-password the group role
        (ROLE, "short", ">= 24"),
    ],
)
def test_role_name_and_password_rules(
    admin_engine: Engine, name: str, password: str, match: str
) -> None:
    with pytest.raises(ProvisionError, match=match), admin_engine.begin() as conn:
        ensure_login_role(conn, name, password)


def test_the_owner_url_cannot_reach_a_service() -> None:
    # Provisioning variables are not settings: a service given them refuses to boot.
    with pytest.raises(SettingsError, match="KEYSTONE_MIGRATION_DATABASE_URL"):
        Settings.from_env(
            {
                "KEYSTONE_DATABASE_URL": "postgresql+psycopg://u:p@h/db",
                "KEYSTONE_REDIS_URL": "redis://r:6379/0",
                "KEYSTONE_AWS_REGION": "eu-west-1",
                "KEYSTONE_OIDC_AUDIENCE": "a",
                "KEYSTONE_MIGRATION_DATABASE_URL": "postgresql+psycopg://owner:pw@h/db",
            }
        )
