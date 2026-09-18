"""External anchoring (Ch. 32/33, A8, R7): Ed25519-signed checkpoints chained to each other.

Each anchor signs {chain_seq, head_hash, anchored_at, prev_anchor_hash}. It is written to the
external write-once store BEFORE the database row commits; the database row and the external
object carry the same bytes. The issuance breaker trips only when the external store has been
unreachable past a threshold — never on worker backlog.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

import redis
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from keystone.audit.canonical import canonicalize
from keystone.audit.chain import GENESIS_PREV_HASH
from keystone.audit.events import AuditEventInput, EventType, format_rfc3339
from keystone.audit.sink import AuditSink
from keystone.audit.store import snapshot_head
from keystone.db.redis import guarded

DEFAULT_BREAKER_THRESHOLD = timedelta(minutes=10)
_UNREACHABLE_SINCE_KEY = "anchor:store_unreachable_since"
_LAST_SUCCESS_KEY = "anchor:last_external_success"


class AnchorStoreUnavailable(Exception):
    """The external write-once store could not be reached or refused the write."""


class AnchorStoreUnreachable(Exception):
    """Breaker tripped (R7): anchor store down past threshold; issuance answers 503."""

    http_status = 503
    code = "AUDIT_ANCHOR_STORE_UNREACHABLE"


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    anchor_seq: int
    chain_seq: int
    head_hash: bytes
    prev_anchor_hash: bytes
    anchored_at: datetime
    signature: bytes
    external_ref: str | None

    @property
    def canonical(self) -> bytes:
        return anchor_canonical(
            self.chain_seq, self.head_hash, self.anchored_at, self.prev_anchor_hash
        )

    @property
    def anchor_hash(self) -> bytes:
        return hashlib.sha256(self.canonical).digest()


def anchor_canonical(
    chain_seq: int, head_hash: bytes, anchored_at: datetime, prev_anchor_hash: bytes
) -> bytes:
    return canonicalize(
        {
            "schema_version": 1,
            "chain_seq": chain_seq,
            "head_hash": head_hash.hex(),
            "anchored_at": format_rfc3339(anchored_at),
            "prev_anchor_hash": prev_anchor_hash.hex(),
        }
    )


class AnchorSigner:
    """Holds the Ed25519 private key in memory only; the key never touches PostgreSQL (A8)."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key

    @classmethod
    def from_pem(cls, pem: bytes) -> AnchorSigner:
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("anchor signing key must be Ed25519")
        return cls(key)

    @classmethod
    def generate(cls) -> AnchorSigner:
        return cls(Ed25519PrivateKey.generate())

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload)

    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def public_pem(self) -> bytes:
        return self.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )


def verify_anchor_signature(public_key: Ed25519PublicKey, record: AnchorRecord) -> bool:
    try:
        public_key.verify(record.signature, record.canonical)
    except Exception:  # noqa: BLE001 — cryptography raises InvalidSignature; any failure is "no"
        return False
    return True


class AnchorStore(Protocol):
    def put(self, chain_seq: int, payload: bytes, signature: bytes) -> str:
        """Write-once; returns an external reference. Raises AnchorStoreUnavailable on failure."""
        ...


class S3ObjectLockAnchorStore:
    """S3 with Object Lock (COMPLIANCE): the object can never be rewritten or deleted early."""

    def __init__(
        self,
        client: Any,
        *,
        bucket: str,
        prefix: str = "anchors/",
        retention_days: int = 400,
        conditional_put: bool = True,
    ) -> None:
        self._client = client
        self._bucket = bucket
        self._prefix = prefix
        self._retention_days = retention_days
        self._conditional = conditional_put

    def _key(self, chain_seq: int) -> str:
        return f"{self._prefix}chain-{chain_seq:016d}.json"

    def put(self, chain_seq: int, payload: bytes, signature: bytes) -> str:
        from botocore.exceptions import BotoCoreError, ClientError

        body = json.dumps(
            {"anchor": payload.decode("utf-8"), "signature": signature.hex()}
        ).encode()
        key = self._key(chain_seq)
        params: dict[str, Any] = {
            "Bucket": self._bucket,
            "Key": key,
            "Body": body,
            "ContentType": "application/json",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": datetime.now(UTC) + timedelta(days=self._retention_days),
        }
        if self._conditional:
            params["IfNoneMatch"] = "*"
        try:
            self._client.put_object(**params)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code == "PreconditionFailed":
                existing = self._client.get_object(Bucket=self._bucket, Key=key)["Body"].read()
                if existing == body:
                    return f"s3://{self._bucket}/{key}"  # already mirrored (retry after crash)
                raise AnchorStoreUnavailable("anchor object exists with different content") from exc
            raise AnchorStoreUnavailable(code or "put failed") from exc
        except BotoCoreError as exc:
            raise AnchorStoreUnavailable(type(exc).__name__) from exc
        return f"s3://{self._bucket}/{key}"


class AnchorBreaker:
    """Tracks external-store reachability in Redis; the API consults it per request (R7)."""

    def __init__(
        self, client: redis.Redis, *, threshold: timedelta = DEFAULT_BREAKER_THRESHOLD
    ) -> None:
        self._redis = client
        self._threshold = threshold

    def record_success(self, now: datetime) -> None:
        def op() -> None:
            pipe = self._redis.pipeline()
            pipe.set(_LAST_SUCCESS_KEY, str(now.timestamp()))
            pipe.delete(_UNREACHABLE_SINCE_KEY)
            pipe.execute()

        guarded(op)

    def record_failure(self, now: datetime) -> None:
        guarded(lambda: self._redis.set(_UNREACHABLE_SINCE_KEY, str(now.timestamp()), nx=True))

    def check(self, now: datetime) -> None:
        raw = cast(bytes | None, guarded(lambda: self._redis.get(_UNREACHABLE_SINCE_KEY)))
        if raw is None:
            return
        since = datetime.fromtimestamp(float(raw), tz=UTC)
        if now - since >= self._threshold:
            raise AnchorStoreUnreachable(f"anchor store unreachable since {since.isoformat()}")


_ANCHOR_COLUMNS = (
    "anchor_seq, chain_seq, head_hash, prev_anchor_hash, anchored_at, signature, external_ref"
)
_LAST_ANCHOR = text(f"SELECT {_ANCHOR_COLUMNS} FROM audit_anchors ORDER BY anchor_seq DESC LIMIT 1")  # noqa: S608
_INSERT_ANCHOR = text(
    "INSERT INTO audit_anchors "
    "(chain_seq, head_hash, prev_anchor_hash, anchored_at, signature, external_ref) "
    "VALUES (:chain_seq, :head_hash, :prev, :at, :sig, :ref) RETURNING anchor_seq"
)
_ANCHORS_IN_RANGE = text(
    f"SELECT {_ANCHOR_COLUMNS} FROM audit_anchors "  # noqa: S608
    "WHERE chain_seq > :lo AND chain_seq <= :hi ORDER BY anchor_seq"
)
_ANCHOR_BEFORE = text(
    f"SELECT {_ANCHOR_COLUMNS} FROM audit_anchors "  # noqa: S608
    "WHERE anchor_seq < :seq ORDER BY anchor_seq DESC LIMIT 1"
)
_HEAD_EVENT_TYPE = text("SELECT event_type FROM audit_events WHERE seq = :seq")


def _record(row: Any) -> AnchorRecord:
    return AnchorRecord(
        anchor_seq=int(row.anchor_seq),
        chain_seq=int(row.chain_seq),
        head_hash=bytes(row.head_hash),
        prev_anchor_hash=bytes(row.prev_anchor_hash),
        anchored_at=row.anchored_at,
        signature=bytes(row.signature),
        external_ref=row.external_ref,
    )


def last_anchor(connection: Connection) -> AnchorRecord | None:
    row = connection.execute(_LAST_ANCHOR).one_or_none()
    return None if row is None else _record(row)


def anchors_in_range(connection: Connection, lo: int, hi: int) -> list[AnchorRecord]:
    return [_record(r) for r in connection.execute(_ANCHORS_IN_RANGE, {"lo": lo, "hi": hi})]


def anchor_before(connection: Connection, anchor_seq: int) -> AnchorRecord | None:
    row = connection.execute(_ANCHOR_BEFORE, {"seq": anchor_seq}).one_or_none()
    return None if row is None else _record(row)


@dataclass(frozen=True, slots=True)
class AnchorOutcome:
    anchored: bool
    chain_seq: int
    reason: str


class Anchorer:
    def __init__(
        self,
        engine: Engine,
        audit: AuditSink,
        signer: AnchorSigner,
        store: AnchorStore,
        breaker: AnchorBreaker,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._engine = engine
        self._audit = audit
        self._signer = signer
        self._store = store
        self._breaker = breaker
        self._clock = clock

    def anchor_once(self) -> AnchorOutcome:
        now = self._clock()
        with self._engine.begin() as conn:
            head = snapshot_head(conn)
            previous = last_anchor(conn)
            prev_hash = previous.anchor_hash if previous else GENESIS_PREV_HASH
            if previous is not None:
                if head.seq == previous.chain_seq:
                    return AnchorOutcome(False, head.seq, "head unchanged")
                head_type = conn.execute(_HEAD_EVENT_TYPE, {"seq": head.seq}).scalar_one_or_none()
                if (
                    head.seq == previous.chain_seq + 1
                    and head_type == EventType.ANCHOR_WRITTEN.value
                ):
                    return AnchorOutcome(False, head.seq, "only the previous anchor event is new")
            payload = anchor_canonical(head.seq, head.head_hash, now, prev_hash)
            signature = self._signer.sign(payload)
            try:
                ref = self._store.put(head.seq, payload, signature)
            except AnchorStoreUnavailable:
                self._breaker.record_failure(now)
                raise
            anchor_seq = conn.execute(
                _INSERT_ANCHOR,
                {
                    "chain_seq": head.seq,
                    "head_hash": head.head_hash,
                    "prev": prev_hash,
                    "at": now,
                    "sig": signature,
                    "ref": ref,
                },
            ).scalar_one()
            self._audit.append(
                conn,
                AuditEventInput(
                    event_type=EventType.ANCHOR_WRITTEN,
                    occurred_at=now,
                    actor="keystone-anchor",
                    data={
                        "anchor_seq": int(anchor_seq),
                        "chain_seq": head.seq,
                        "head_hash": head.head_hash.hex(),
                        "external_ref": ref,
                    },
                ),
            )
        self._breaker.record_success(now)
        return AnchorOutcome(True, head.seq, "anchored")
