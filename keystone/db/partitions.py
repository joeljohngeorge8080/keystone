"""Monthly range partitions for audit_events (Ch. 34); retention = DROP PARTITION."""

from collections.abc import Iterator
from datetime import date

from psycopg import sql
from psycopg.connection import Connection as PsycopgConnection
from sqlalchemy.engine import Connection


def month_starts(start: date, *, count: int) -> Iterator[date]:
    year, month = start.year, start.month
    for _ in range(count):
        yield date(year, month, 1)
        month += 1
        if month == 13:
            year, month = year + 1, 1


def _next_month(month: date) -> date:
    return date(month.year + (month.month == 12), month.month % 12 + 1, 1)


def audit_partition_name(month: date) -> str:
    return f"audit_events_{month.year:04d}{month.month:02d}"


def ensure_audit_partition(connection: Connection, month: date) -> None:
    month = month.replace(day=1)
    raw = connection.connection.driver_connection
    if not isinstance(raw, PsycopgConnection):
        raise TypeError("audit partitions require a psycopg connection")
    statement = sql.SQL(
        "CREATE TABLE IF NOT EXISTS {name} PARTITION OF audit_events "
        "FOR VALUES FROM ({lo}) TO ({hi})"
    ).format(
        name=sql.Identifier(audit_partition_name(month)),
        lo=sql.Literal(month.isoformat()),
        hi=sql.Literal(_next_month(month).isoformat()),
    )
    raw.execute(statement)
