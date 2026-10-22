"""Admin bearer tokens (Ch. 37/48, TB6): hash-stored, 90-day cap, every issue/revoke audited.

Only SHA-256(token) is persisted; a presented token is looked up by its hash, so the plaintext
exists in exactly one place: the response that created it (or the host secret store, for the
bootstrap token). Bootstrap: when no admin principal exists at all, the env-injected
KEYSTONE_ADMIN_BOOTSTRAP_TOKEN is registered once, for 24 h, under the `bootstrap` principal; the
operator uses it to issue real tokens and then revokes it.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import JsonValue
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import AuditSink
from keystone.db.ids import uuid7

TOKEN_PREFIX = "ksa_"  # noqa: S105 — public prefix, not a secret
MAX_TOKEN_TTL = timedelta(days=90)
BOOTSTRAP_PRINCIPAL = "bootstrap"
BOOTSTRAP_TTL = timedelta(hours=24)
PRINCIPAL_PATTERN = r"^[a-z0-9][a-z0-9._-]{1,63}$"


class AdminAuthFailed(Exception):
    """Missing, malformed, unknown, expired or revoked bearer, or a disabled principal."""

    http_status = 401
    code = "ADMIN_TOKEN_INVALID"


class AdminTokenNotFound(Exception):
    http_status = 404
    code = "ADMIN_TOKEN_NOT_FOUND"


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    id: uuid.UUID
    name: str


@dataclass(frozen=True, slots=True)
class AdminTokenRecord:
    id: uuid.UUID
    principal: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class IssuedAdminToken:
    """The plaintext is returned to the caller once and never stored or audited."""

    token: str
    record: AdminTokenRecord
    audit_seq: int

    def __repr__(self) -> str:
        return f"IssuedAdminToken(id={self.record.id}, principal={self.record.principal})"

    __str__ = __repr__


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


_AUTHENTICATE = text(
    "SELECT p.id, p.name FROM admin_tokens t JOIN admin_principals p "
    "ON p.id = t.admin_principal_id "
    "WHERE t.token_hash = :hash AND t.revoked_at IS NULL AND t.expires_at > :now AND p.enabled"
)
_PRINCIPAL_BY_NAME = text("SELECT id, name FROM admin_principals WHERE name = :name")
_INSERT_PRINCIPAL = text("INSERT INTO admin_principals (id, name) VALUES (:id, :name)")
_ANY_PRINCIPAL = text("SELECT EXISTS (SELECT 1 FROM admin_principals)")
_INSERT_TOKEN = text(
    "INSERT INTO admin_tokens (id, admin_principal_id, token_hash, created_at, expires_at) "
    "VALUES (:id, :principal_id, :hash, :created_at, :expires_at)"
)
_RECORD_SELECT = (
    "SELECT t.id, p.name AS principal, t.created_at, t.expires_at, t.revoked_at "
    "FROM admin_tokens t JOIN admin_principals p ON p.id = t.admin_principal_id"
)
_LIST = text(_RECORD_SELECT + " ORDER BY t.created_at DESC")
_GET = text(_RECORD_SELECT + " WHERE t.id = :id")
_REVOKE = text("UPDATE admin_tokens SET revoked_at = :now WHERE id = :id AND revoked_at IS NULL")
_LOCK = text("SELECT pg_advisory_xact_lock(hashtext('admin_principals'))")


def _record(row: object) -> AdminTokenRecord:
    return AdminTokenRecord(
        id=row.id,  # type: ignore[attr-defined]
        principal=row.principal,  # type: ignore[attr-defined]
        created_at=row.created_at,  # type: ignore[attr-defined]
        expires_at=row.expires_at,  # type: ignore[attr-defined]
        revoked_at=row.revoked_at,  # type: ignore[attr-defined]
    )


class AdminTokenRepository:
    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def authenticate(self, token: str, now: datetime) -> AdminPrincipal | None:
        if not 32 <= len(token) <= 512:  # bootstrap tokens are >= 32 chars, issued ones ~47
            return None
        row = self._conn.execute(
            _AUTHENTICATE, {"hash": token_hash(token), "now": now}
        ).one_or_none()
        return None if row is None else AdminPrincipal(id=row.id, name=row.name)

    def find_principal(self, name: str) -> AdminPrincipal | None:
        row = self._conn.execute(_PRINCIPAL_BY_NAME, {"name": name}).one_or_none()
        return None if row is None else AdminPrincipal(id=row.id, name=row.name)

    def ensure_principal(self, name: str) -> AdminPrincipal:
        existing = self.find_principal(name)
        if existing is not None:
            return existing
        principal_id = uuid7()
        self._conn.execute(_INSERT_PRINCIPAL, {"id": principal_id, "name": name})
        return AdminPrincipal(id=principal_id, name=name)

    def any_principal(self) -> bool:
        return bool(self._conn.execute(_ANY_PRINCIPAL).scalar_one())

    def insert(
        self, principal: AdminPrincipal, digest: bytes, created_at: datetime, expires_at: datetime
    ) -> AdminTokenRecord:
        token_id = uuid7()
        self._conn.execute(
            _INSERT_TOKEN,
            {
                "id": token_id,
                "principal_id": principal.id,
                "hash": digest,
                "created_at": created_at,
                "expires_at": expires_at,
            },
        )
        return AdminTokenRecord(token_id, principal.name, created_at, expires_at, None)

    def list(self) -> list[AdminTokenRecord]:
        return [_record(row) for row in self._conn.execute(_LIST)]

    def get(self, token_id: uuid.UUID) -> AdminTokenRecord | None:
        row = self._conn.execute(_GET, {"id": token_id}).one_or_none()
        return None if row is None else _record(row)

    def revoke(self, token_id: uuid.UUID, now: datetime) -> bool:
        return self._conn.execute(_REVOKE, {"id": token_id, "now": now}).rowcount == 1


class AdminTokenService:
    def __init__(
        self,
        engine: Engine,
        audit: AuditSink,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._engine = engine
        self._audit = audit
        self._clock = clock

    def authenticate(self, token: str) -> AdminPrincipal:
        with self._engine.connect() as conn:
            principal = AdminTokenRepository(conn).authenticate(token, self._clock())
        if principal is None:
            raise AdminAuthFailed("admin bearer token rejected")
        return principal

    def issue(
        self, *, principal_name: str, ttl: timedelta, issued_by: AdminPrincipal
    ) -> IssuedAdminToken:
        if not timedelta(0) < ttl <= MAX_TOKEN_TTL:
            raise ValueError("admin token ttl must be within (0, 90 days]")
        token = new_token()
        now = self._clock()
        with self._engine.begin() as conn:
            repo = AdminTokenRepository(conn)
            conn.execute(_LOCK)
            principal = repo.ensure_principal(principal_name)
            record = repo.insert(principal, token_hash(token), now, now + ttl)
            seq = self._append(conn, EventType.ADMIN_TOKEN_ISSUED, record, issued_by)
        return IssuedAdminToken(token=token, record=record, audit_seq=seq)

    def revoke(self, token_id: uuid.UUID, *, revoked_by: AdminPrincipal) -> AdminTokenRecord:
        now = self._clock()
        with self._engine.begin() as conn:
            repo = AdminTokenRepository(conn)
            record = repo.get(token_id)
            if record is None:
                raise AdminTokenNotFound(str(token_id))
            if repo.revoke(token_id, now):
                record = AdminTokenRecord(
                    record.id, record.principal, record.created_at, record.expires_at, now
                )
                self._append(conn, EventType.ADMIN_TOKEN_REVOKED, record, revoked_by)
        return record  # revoking an already-revoked token is idempotent and not re-audited

    def list(self) -> list[AdminTokenRecord]:
        with self._engine.connect() as conn:
            return AdminTokenRepository(conn).list()

    def bootstrap(self, token: str) -> AdminTokenRecord | None:
        """Register the bootstrap token iff no admin principal exists; None when not needed."""
        now = self._clock()
        with self._engine.begin() as conn:
            conn.execute(_LOCK)  # two booting processes cannot both bootstrap
            repo = AdminTokenRepository(conn)
            if repo.any_principal():
                return None
            principal = repo.ensure_principal(BOOTSTRAP_PRINCIPAL)
            record = repo.insert(principal, token_hash(token), now, now + BOOTSTRAP_TTL)
            self._append(conn, EventType.ADMIN_TOKEN_ISSUED, record, None)
        return record

    def _append(
        self,
        conn: Connection,
        event_type: EventType,
        record: AdminTokenRecord,
        by: AdminPrincipal | None,
    ) -> int:
        data: dict[str, JsonValue] = {
            "admin_token_id": str(record.id),
            "principal": record.principal,
            "expires_at": record.expires_at.astimezone(UTC).isoformat(),
        }
        if by is None:
            data["bootstrap"] = True
        return self._audit.append(
            conn,
            AuditEventInput(
                event_type=event_type,
                occurred_at=self._clock(),
                actor=by.name if by else "system:bootstrap",
                admin_principal_id=by.id if by else None,
                data=data,
            ),
        ).seq
