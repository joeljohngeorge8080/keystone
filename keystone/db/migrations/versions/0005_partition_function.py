"""Least-privilege audit partition pre-creation for the worker.

`keystone_app` has no CREATE on the schema and does not own `audit_events`, so the daily
`ensure_partitions` task could not create next month's partition, and once the months seeded by
0001 ran out every audit insert (and so every issuance) would fail closed. This SECURITY DEFINER
function, owned by the migration role, lets the app role create exactly one thing: a correctly
named monthly partition of `audit_events`, for a month in a bounded window around now.

Revision ID: 0005
Revises: 0004
"""

from alembic import op

revision = "0005"
down_revision = "0004"

_DDL = r"""
CREATE FUNCTION keystone_ensure_audit_partition(month DATE) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
DECLARE
    lo   DATE := date_trunc('month', month)::date;
    hi   DATE := (date_trunc('month', month) + interval '1 month')::date;
    name TEXT := 'audit_events_' || to_char(month, 'YYYYMM');
BEGIN
    IF month IS NULL OR month <> lo THEN
        RAISE EXCEPTION 'partition month must be the first day of a month';
    END IF;
    IF lo < (date_trunc('month', now()) - interval '1 month')
       OR lo > (date_trunc('month', now()) + interval '24 months') THEN
        RAISE EXCEPTION 'partition month % is outside the pre-creation window', lo;
    END IF;
    IF to_regclass(name) IS NOT NULL THEN
        RETURN false;
    END IF;
    EXECUTE format(
        'CREATE TABLE %I PARTITION OF audit_events FOR VALUES FROM (%L) TO (%L)', name, lo, hi
    );
    RETURN true;
END
$fn$;

REVOKE ALL ON FUNCTION keystone_ensure_audit_partition(DATE) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keystone_ensure_audit_partition(DATE) TO keystone_app;
"""


def upgrade() -> None:
    op.execute(_DDL)


def downgrade() -> None:
    raise RuntimeError("forward-only (Ch. 62)")
