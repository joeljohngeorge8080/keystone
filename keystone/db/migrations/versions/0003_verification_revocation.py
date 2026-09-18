"""Verification checkpoint (R7) and revocation tracking (Ch. 26 / F6).

Revision ID: 0003
Revises: 0002
"""

from alembic import op

revision = "0003"
down_revision = "0002"

_DDL = r"""
CREATE TABLE audit_verification_state (
    singleton           SMALLINT    PRIMARY KEY CHECK (singleton = 1),
    last_verified_seq   BIGINT      NOT NULL CHECK (last_verified_seq >= 0),
    last_verified_hash  BYTEA       NOT NULL CHECK (octet_length(last_verified_hash) = 32),
    last_anchor_seq     BIGINT      NOT NULL DEFAULT 0,
    verified_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO audit_verification_state (singleton, last_verified_seq, last_verified_hash)
VALUES (1, 0, decode(repeat('00', 32), 'hex'));

CREATE TABLE revocations (
    id               UUID        PRIMARY KEY,
    target_role_id   UUID        NOT NULL REFERENCES target_roles(id) ON DELETE RESTRICT,
    not_before       TIMESTAMPTZ NOT NULL,
    mechanism        TEXT        NOT NULL CHECK (mechanism IN ('runbook', 'iam_deny_policy')),
    state            TEXT        NOT NULL CHECK (state IN ('flagged', 'applied', 'failed')),
    policy_name      TEXT        NULL,
    flagged_by       TEXT        NOT NULL,
    flagged_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at       TIMESTAMPTZ NULL,
    CHECK (state <> 'applied' OR applied_at IS NOT NULL)
);
CREATE INDEX revocations_open ON revocations (state, flagged_at) WHERE state = 'flagged';

GRANT SELECT, UPDATE ON audit_verification_state TO keystone_app;
GRANT SELECT, INSERT, UPDATE ON revocations TO keystone_app;
"""


def upgrade() -> None:
    op.execute(_DDL)


def downgrade() -> None:
    raise RuntimeError("forward-only (Ch. 62)")
