"""Audit chain: append-only partitioned audit_events, singleton chain head, app role grants.

Spec: Ch. 33/34/36/37/38 + R1 (canonical_payload authoritative, details projection).
Revision ID: 0001
Revises: None
"""

from datetime import UTC, datetime

from alembic import op

from keystone.db.partitions import ensure_audit_partition, month_starts

revision = "0001"
down_revision = None

_DDL = """
CREATE TABLE audit_chain_head (
    singleton  SMALLINT PRIMARY KEY CHECK (singleton = 1),
    seq        BIGINT   NOT NULL CHECK (seq >= 0),
    head_hash  BYTEA    NOT NULL CHECK (octet_length(head_hash) = 32)
);
INSERT INTO audit_chain_head (singleton, seq, head_hash)
VALUES (1, 0, decode(repeat('00', 32), 'hex'));

CREATE TABLE audit_events (
    seq                 BIGINT      NOT NULL,
    id                  UUID        NOT NULL,
    event_type          TEXT        NOT NULL,
    issuance_id         UUID        NULL,
    admin_principal_id  UUID        NULL,
    input_hash          TEXT        NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
    policy_digest       TEXT        NULL,
    occurred_at         TIMESTAMPTZ NOT NULL,
    details             JSONB       NULL,
    canonical_payload   BYTEA       NOT NULL,
    prev_hash           BYTEA       NOT NULL CHECK (octet_length(prev_hash) = 32),
    event_hash          BYTEA       NOT NULL CHECK (octet_length(event_hash) = 32),
    PRIMARY KEY (seq, occurred_at),
    UNIQUE (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX audit_events_occurred_at_brin ON audit_events USING BRIN (occurred_at);
CREATE INDEX audit_events_type_time ON audit_events (event_type, occurred_at);
CREATE INDEX audit_events_issuance ON audit_events (issuance_id);

CREATE FUNCTION audit_events_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: % rejected', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;
CREATE TRIGGER audit_events_no_rewrite
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();
CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'keystone_app') THEN
        CREATE ROLE keystone_app NOLOGIN;
    END IF;
END
$$;
GRANT USAGE ON SCHEMA public TO keystone_app;
GRANT SELECT, INSERT ON audit_events TO keystone_app;
GRANT SELECT, UPDATE ON audit_chain_head TO keystone_app;
"""


def upgrade() -> None:
    op.execute(_DDL)
    connection = op.get_bind()
    for month in month_starts(datetime.now(UTC).date(), count=14):
        ensure_audit_partition(connection, month)


def downgrade() -> None:
    raise RuntimeError("audit chain migration is forward-only (Ch. 62)")
