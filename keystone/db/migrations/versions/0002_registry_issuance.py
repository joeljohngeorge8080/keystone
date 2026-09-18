# ruff: noqa: E501 — DDL is clearer on one line per column
"""Registry, policy pins, admin auth, issuances, rate-limit overrides, anchors.

Spec: Ch. 22 (registry), 24 (issuance states, AMB-3), 36-38 (tables, indexes, constraints),
A2 (TTL 900-3600 CHECKs), R8 (CI-assigned bundle_sequence), AMB-2 (jti_hash raw 32 bytes),
AMB-4 (session_name unique join key), Ch. 23 (inline session policy <= 2048 chars).
Revision ID: 0002
Revises: 0001
"""

from alembic import op

revision = "0002"
down_revision = "0001"

_DDL = r"""
CREATE TABLE admin_principals (
    id          UUID        PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._-]{1,63}$'),
    enabled     BOOLEAN     NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE admin_tokens (
    id                  UUID        PRIMARY KEY,
    admin_principal_id  UUID        NOT NULL REFERENCES admin_principals(id) ON DELETE RESTRICT,
    token_hash          BYTEA       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ NULL,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '90 days')
);

CREATE TABLE target_roles (
    id               UUID        PRIMARY KEY,
    name             TEXT        NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9-]{1,63}$'),
    role_arn         TEXT        NOT NULL UNIQUE
                     CHECK (role_arn ~ '^arn\:aws\:iam\:\:[0-9]{12}\:role/[A-Za-z0-9+=,.@_/-]+$'
                            AND length(role_arn) <= 2048),
    max_ttl_seconds  INTEGER     NOT NULL CHECK (max_ttl_seconds BETWEEN 900 AND 3600),
    external_id      TEXT        NULL CHECK (external_id IS NULL OR length(external_id) BETWEEN 2 AND 1224),
    enabled          BOOLEAN     NOT NULL DEFAULT true,
    description      TEXT        NOT NULL DEFAULT '',
    owner            TEXT        NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE session_policy_templates (
    id               UUID        PRIMARY KEY,
    target_role_id   UUID        NOT NULL REFERENCES target_roles(id) ON DELETE RESTRICT,
    ref              TEXT        NOT NULL CHECK (ref ~ '^[a-z0-9][a-z0-9-]{1,63}$'),
    policy_document  JSONB       NOT NULL CHECK (length(CAST(policy_document AS text)) <= 2048),
    enabled          BOOLEAN     NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_role_id, ref)
);

CREATE TABLE policy_pins (
    id               UUID        PRIMARY KEY,
    bundle_digest    TEXT        NOT NULL CHECK (bundle_digest ~ '^sha256:[0-9a-f]{64}$'),
    bundle_sequence  INTEGER     NOT NULL CHECK (bundle_sequence >= 0),
    active           BOOLEAN     NOT NULL DEFAULT false,
    forced_rollback  BOOLEAN     NOT NULL DEFAULT false,
    pinned_by        UUID        NULL REFERENCES admin_principals(id) ON DELETE RESTRICT,
    pinned_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX policy_pins_one_active ON policy_pins (active) WHERE active;
CREATE INDEX policy_pins_sequence ON policy_pins (bundle_sequence DESC);

CREATE TABLE issuances (
    id                   UUID        PRIMARY KEY,
    jti_hash             BYTEA       NOT NULL UNIQUE CHECK (octet_length(jti_hash) = 32),
    target_role_id       UUID        NOT NULL REFERENCES target_roles(id) ON DELETE RESTRICT,
    policy_pin_id        UUID        NOT NULL REFERENCES policy_pins(id) ON DELETE RESTRICT,
    state                TEXT        NOT NULL CHECK (state IN
                         ('requested', 'authorized', 'issued', 'delivered', 'failed', 'indeterminate')),
    grant_name           TEXT        NOT NULL CHECK (grant_name ~ '^[a-z0-9][a-z0-9-]{1,63}$'),
    session_name         TEXT        NOT NULL UNIQUE CHECK (session_name ~ '^[A-Za-z0-9+=,.@_-]{2,64}$'),
    session_policy_ref   TEXT        NULL,
    access_key_prefix    TEXT        NULL CHECK (access_key_prefix IS NULL OR access_key_prefix ~ '^[A-Z0-9]{4,8}$'),
    granted_ttl_seconds  INTEGER     NOT NULL CHECK (granted_ttl_seconds BETWEEN 900 AND 3600),
    expires_at           TIMESTAMPTZ NULL,
    identity_claims      JSONB       NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX issuances_expires_at ON issuances (expires_at);
CREATE INDEX issuances_role_time ON issuances (target_role_id, created_at DESC);
CREATE INDEX issuances_repository_time ON issuances ((identity_claims->>'repository'), created_at DESC);
CREATE INDEX issuances_non_terminal ON issuances (state, created_at)
    WHERE state NOT IN ('delivered', 'failed');

CREATE TABLE rate_limit_overrides (
    id          UUID        PRIMARY KEY,
    scope       TEXT        NOT NULL CHECK (scope IN ('repository', 'role')),
    subject     TEXT        NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
    per_minute  INTEGER     NOT NULL CHECK (per_minute BETWEEN 0 AND 10000),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope, subject)
);

CREATE TABLE audit_anchors (
    anchor_seq        BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    chain_seq         BIGINT      NOT NULL,
    head_hash         BYTEA       NOT NULL CHECK (octet_length(head_hash) = 32),
    prev_anchor_hash  BYTEA       NOT NULL CHECK (octet_length(prev_anchor_hash) = 32),
    anchored_at       TIMESTAMPTZ NOT NULL,
    signature         BYTEA       NOT NULL CHECK (octet_length(signature) = 64),
    external_ref      TEXT        NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER audit_anchors_no_rewrite
    BEFORE UPDATE OR DELETE ON audit_anchors
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();
CREATE TRIGGER audit_anchors_no_truncate
    BEFORE TRUNCATE ON audit_anchors
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();

ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_issuance_fk
    FOREIGN KEY (issuance_id) REFERENCES issuances(id) ON DELETE RESTRICT;

GRANT SELECT, INSERT, UPDATE ON target_roles, session_policy_templates, policy_pins,
    admin_principals, admin_tokens, rate_limit_overrides, issuances TO keystone_app;
GRANT SELECT, INSERT ON audit_anchors TO keystone_app;
"""


def upgrade() -> None:
    op.execute(_DDL)


def downgrade() -> None:
    raise RuntimeError("registry/issuance migration is forward-only (Ch. 62)")
