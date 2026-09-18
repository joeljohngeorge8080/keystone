import os

from alembic import context
from sqlalchemy import create_engine


def _database_url() -> str:
    url = context.config.get_main_option("sqlalchemy.url") or os.environ.get(
        "KEYSTONE_DATABASE_URL"
    )
    if not url:
        raise RuntimeError("set KEYSTONE_DATABASE_URL (never pass credentials on argv)")
    return url


def run_migrations_online() -> None:
    engine = create_engine(_database_url())
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("offline SQL generation is not supported; run against a database")
run_migrations_online()
