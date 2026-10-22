"""Deployment init step (Ch. 62): migrate, pre-create partitions, ensure the service login role.

Run once per deploy, before the services start, as the role that owns the schema:

    python -m keystone.db.provision

Reads `KEYSTONE_MIGRATION_DATABASE_URL` (the owner connection) and creates or re-passwords the
service login role named by `KEYSTONE_APP_DB_ROLE` (member of `keystone_app`, nothing more) with
the password in `KEYSTONE_APP_DB_PASSWORD` (Ch. 48 env injection) or in the file named by
`KEYSTONE_APP_DB_PASSWORD_FILE` (a mounted secret), exactly one. These names are deliberately not
service settings: `Settings` refuses unknown KEYSTONE_* keys,
so the owner URL leaking into a service's environment stops that service from booting instead
of handing it DDL rights.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from datetime import UTC, datetime

from alembic import command
from alembic.config import Config
from psycopg import sql
from psycopg.connection import Connection as PsycopgConnection
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection

from keystone.db.partitions import ensure_audit_partition, month_starts

MIGRATION_URL_ENV = "KEYSTONE_MIGRATION_DATABASE_URL"
APP_ROLE_ENV = "KEYSTONE_APP_DB_ROLE"
APP_PASSWORD_ENV = "KEYSTONE_APP_DB_PASSWORD"  # noqa: S105 — variable name
APP_PASSWORD_FILE_ENV = "KEYSTONE_APP_DB_PASSWORD_FILE"  # noqa: S105 — variable name
APP_GROUP_ROLE = "keystone_app"
PARTITION_MONTHS_AHEAD = 14
_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_MIN_PASSWORD_LENGTH = 24
_CREATE_ROLE = sql.SQL("CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {pw}")
_ALTER_ROLE = sql.SQL("ALTER ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {pw}")


class ProvisionError(Exception):
    pass


def _raw(connection: Connection) -> PsycopgConnection[object]:
    raw = connection.connection.driver_connection
    if not isinstance(raw, PsycopgConnection):
        raise ProvisionError("provisioning requires a psycopg connection")
    return raw


def ensure_login_role(connection: Connection, name: str, password: str) -> bool:
    """Create the service login role (or reset its password); returns True when created.

    The role is a member of `keystone_app` and inherits only its grants; identifiers and the
    password are quoted by psycopg, never interpolated."""
    if not _ROLE_NAME.match(name) or name == APP_GROUP_ROLE:
        raise ProvisionError(f"{APP_ROLE_ENV} must be a plain lowercase role name")
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ProvisionError(f"the service role password must be >= {_MIN_PASSWORD_LENGTH} chars")
    exists = connection.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :name"), {"name": name}
    ).scalar()
    statement = _ALTER_ROLE if exists else _CREATE_ROLE
    raw = _raw(connection)
    raw.execute(statement.format(role=sql.Identifier(name), pw=sql.Literal(password)))
    raw.execute(
        sql.SQL("GRANT {group} TO {role}").format(
            group=sql.Identifier(APP_GROUP_ROLE), role=sql.Identifier(name)
        )
    )
    return not exists


def _app_password(environ: Mapping[str, str]) -> str:
    inline = environ.get(APP_PASSWORD_ENV)
    path = environ.get(APP_PASSWORD_FILE_ENV)
    if bool(inline) == bool(path):
        raise ProvisionError(f"set exactly one of {APP_PASSWORD_ENV} and {APP_PASSWORD_FILE_ENV}")
    if inline:
        return inline
    assert path is not None
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


def provision(environ: Mapping[str, str], *, alembic_ini: str = "alembic.ini") -> None:
    url = environ.get(MIGRATION_URL_ENV)
    role = environ.get(APP_ROLE_ENV)
    if not url or not role:
        raise ProvisionError(f"set {MIGRATION_URL_ENV} and {APP_ROLE_ENV}")
    password = _app_password(environ)

    config = Config(alembic_ini)
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    command.upgrade(config, "head")

    engine = create_engine(url)
    try:
        with engine.begin() as conn:
            for month in month_starts(datetime.now(UTC).date(), count=PARTITION_MONTHS_AHEAD):
                ensure_audit_partition(conn, month)
            ensure_login_role(conn, role, password)
    finally:
        engine.dispose()


def main() -> int:
    try:
        provision(os.environ)
    except (ProvisionError, OSError) as exc:
        sys.stderr.write(f"provision: {exc}\n")
        return 2
    sys.stdout.write("provision: schema at head, partitions ensured, service role ready\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
