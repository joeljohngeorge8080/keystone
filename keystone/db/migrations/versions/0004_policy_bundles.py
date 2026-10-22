"""Staged policy bundles, persisted so a restarted admin plane can keep serving OPA (R5).

The bytes are the OPA-signed bundle exactly as pinned; on boot the admin plane re-proves the
content-digest revision before serving them again. Append-only: a digest's bytes never change.

Revision ID: 0004
Revises: 0003
"""

from alembic import op

revision = "0004"
down_revision = "0003"

_DDL = r"""
CREATE TABLE policy_bundles (
    digest     TEXT        PRIMARY KEY CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    bundle     BYTEA       NOT NULL CHECK (octet_length(bundle) BETWEEN 1 AND 16777216),
    staged_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER policy_bundles_no_rewrite
    BEFORE UPDATE OR DELETE ON policy_bundles
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();

GRANT SELECT, INSERT ON policy_bundles TO keystone_app;
"""


def upgrade() -> None:
    op.execute(_DDL)


def downgrade() -> None:
    raise RuntimeError("forward-only (Ch. 62)")
