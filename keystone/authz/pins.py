"""Two-phase policy pin activation (R5) with a CI-assigned monotonic sequence (R8).

Load phase: stage bundle X where OPA's bundle plugin fetches it, then poll OPA until it reports
`revision == X`. Commit phase: only then write the DB pin (audited `admin_policy_pinned`).
A load timeout leaves the pin unchanged (409). Rollback to a lower sequence requires
`force_rollback` and emits a loud `admin_policy_rollback` event.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import httpx
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import AuditSink
from keystone.authz.bundles import BundleManifest, inspect_bundle
from keystone.authz.service import ActivePin, active_pin
from keystone.db.ids import uuid7

DEFAULT_LOAD_TIMEOUT_SECONDS = 30.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.5


class PolicyLoadTimeout(Exception):
    http_status = 409
    code = "POLICY_LOAD_TIMEOUT"


class PinSequenceRejected(Exception):
    http_status = 409
    code = "POLICY_PIN_SEQUENCE_REJECTED"


class BundleGateway(Protocol):
    def stage(self, digest: str, bundle: bytes) -> None: ...

    def loaded_digest(self) -> str | None: ...


class StagedBundleStore:
    """Thread-safe holder of the bundle OPA should load next; the admin plane serves it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._digest: str | None = None
        self._bundle: bytes | None = None

    def put(self, digest: str, bundle: bytes) -> None:
        with self._lock:
            self._digest, self._bundle = digest, bundle

    def current(self) -> tuple[str, bytes] | None:
        with self._lock:
            if self._digest is None or self._bundle is None:
                return None
            return self._digest, self._bundle


class OpaBundleGateway:
    def __init__(
        self, store: StagedBundleStore, opa_base_url: str, *, client: httpx.Client | None = None
    ) -> None:
        self._store = store
        self._url = opa_base_url.rstrip("/") + "/v1/data/system/bundles"
        self._client = client or httpx.Client(timeout=1.0)

    def stage(self, digest: str, bundle: bytes) -> None:
        self._store.put(digest, bundle)

    def loaded_digest(self) -> str | None:
        try:
            response = self._client.get(self._url)
        except httpx.HTTPError:
            return None
        if response.status_code != 200:
            return None
        result = response.json().get("result") or {}
        revisions = {
            str((entry.get("manifest") or {}).get("revision") or "")
            for entry in result.values()
            if isinstance(entry, dict)
        }
        revisions.discard("")
        return revisions.pop() if len(revisions) == 1 else None


_DEACTIVATE = text("UPDATE policy_pins SET active = false WHERE active")
_INSERT = text(
    "INSERT INTO policy_pins "
    "(id, bundle_digest, bundle_sequence, active, forced_rollback, pinned_by) "
    "VALUES (:id, :digest, :sequence, true, :forced, :pinned_by)"
)
_LOCK = text("SELECT pg_advisory_xact_lock(hashtext('policy_pins'))")
_HISTORY = text(
    "SELECT p.id, p.bundle_digest, p.bundle_sequence, p.active, p.forced_rollback, "
    "p.pinned_at, a.name AS pinned_by FROM policy_pins p "
    "LEFT JOIN admin_principals a ON a.id = p.pinned_by "
    "ORDER BY p.pinned_at DESC, p.id DESC LIMIT :limit"
)


@dataclass(frozen=True, slots=True)
class PinRecord:
    id: uuid.UUID
    bundle_digest: str
    bundle_sequence: int
    active: bool
    forced_rollback: bool
    pinned_at: datetime
    pinned_by: str | None


@dataclass(frozen=True, slots=True)
class PinResult:
    pin: ActivePin
    manifest: BundleManifest
    rolled_back: bool
    audit_seq: int


class PolicyPinRepository:
    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def history(self, limit: int = 50) -> list[PinRecord]:
        return [
            PinRecord(
                id=row.id,
                bundle_digest=row.bundle_digest,
                bundle_sequence=int(row.bundle_sequence),
                active=row.active,
                forced_rollback=row.forced_rollback,
                pinned_at=row.pinned_at,
                pinned_by=row.pinned_by,
            )
            for row in self._conn.execute(_HISTORY, {"limit": limit})
        ]

    def commit_pin(
        self,
        manifest: BundleManifest,
        *,
        pinned_by: uuid.UUID | None,
        force_rollback: bool,
    ) -> tuple[ActivePin, bool]:
        self._conn.execute(_LOCK)  # serialize activations
        current = active_pin(self._conn)
        rolled_back = False
        if current is not None and manifest.bundle_sequence <= current.bundle_sequence:
            if current.bundle_digest == manifest.revision:
                return current, False  # idempotent re-pin of the live bundle
            if not force_rollback:
                raise PinSequenceRejected(
                    f"sequence {manifest.bundle_sequence} is not above "
                    f"active {current.bundle_sequence}"
                )
            rolled_back = True
        self._conn.execute(_DEACTIVATE)
        pin_id = uuid7()
        self._conn.execute(
            _INSERT,
            {
                "id": pin_id,
                "digest": manifest.revision,
                "sequence": manifest.bundle_sequence,
                "forced": rolled_back,
                "pinned_by": pinned_by,
            },
        )
        return ActivePin(
            id=pin_id, bundle_digest=manifest.revision, bundle_sequence=manifest.bundle_sequence
        ), rolled_back


class PinActivator:
    def __init__(
        self,
        engine: Engine,
        audit: AuditSink,
        gateway: BundleGateway,
        *,
        load_timeout_seconds: float = DEFAULT_LOAD_TIMEOUT_SECONDS,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._engine = engine
        self._audit = audit
        self._gateway = gateway
        self._timeout = load_timeout_seconds
        self._poll = poll_interval_seconds
        self._clock = clock
        self._sleep = sleep

    def activate(
        self,
        bundle: bytes,
        *,
        pinned_by: uuid.UUID | None,
        actor: str,
        force_rollback: bool = False,
    ) -> PinResult:
        manifest = inspect_bundle(bundle)  # signed, revision proven against contents, R8 sequence
        with self._engine.connect() as conn:
            current = active_pin(conn)
        if (
            current is not None
            and manifest.bundle_sequence <= current.bundle_sequence
            and current.bundle_digest != manifest.revision
            and not force_rollback
        ):
            raise PinSequenceRejected("refusing to load a bundle that could not be pinned")

        # ---- load phase: OPA must confirm before anything is committed ----
        self._gateway.stage(manifest.revision, bundle)
        deadline = time.monotonic() + self._timeout
        while self._gateway.loaded_digest() != manifest.revision:
            if time.monotonic() >= deadline:
                raise PolicyLoadTimeout(
                    f"OPA did not report {manifest.revision} within {self._timeout}s"
                )
            self._sleep(self._poll)

        # ---- commit phase: pin + audit in one transaction ----
        with self._engine.begin() as conn:
            pin, rolled_back = PolicyPinRepository(conn).commit_pin(
                manifest, pinned_by=pinned_by, force_rollback=force_rollback
            )
            event = AuditEventInput(
                event_type=EventType.ADMIN_POLICY_ROLLBACK
                if rolled_back
                else EventType.ADMIN_POLICY_PINNED,
                occurred_at=self._clock(),
                actor=actor,
                admin_principal_id=pinned_by,
                policy_digest=manifest.revision,
                data={
                    "bundle_digest": manifest.revision,
                    "bundle_sequence": manifest.bundle_sequence,
                    "previous_digest": current.bundle_digest if current else None,
                    "previous_sequence": current.bundle_sequence if current else None,
                    "forced_rollback": rolled_back,
                },
            )
            seq = self._audit.append(conn, event).seq
        return PinResult(pin=pin, manifest=manifest, rolled_back=rolled_back, audit_seq=seq)


def opa_config_yaml(
    *,
    bundle_service_url: str,
    resource: str,
    verification_key_pem: str,
    poll_seconds: int = 5,
    bearer_token_path: str | None = None,
) -> str:
    """OPA sidecar config: poll Keystone's admin plane for the bundle and verify its signature.

    `bearer_token_path` points OPA at a file holding the bundle-service token, so the secret is
    never written into the config itself."""
    indented_key = "\n".join("      " + line for line in verification_key_pem.strip().splitlines())
    credentials = (
        f"    credentials:\n      bearer:\n        token_path: {json.dumps(bearer_token_path)}\n"
        if bearer_token_path
        else ""
    )
    return (
        "services:\n"
        f"  keystone:\n    url: {bundle_service_url}\n"
        f"{credentials}"
        "bundles:\n"
        "  keystone:\n"
        "    service: keystone\n"
        f"    resource: {resource}\n"
        "    polling:\n"
        f"      min_delay_seconds: {poll_seconds}\n"
        f"      max_delay_seconds: {poll_seconds}\n"
        "    signing:\n      keyid: keystone\n"
        "keys:\n"
        "  keystone:\n    algorithm: RS256\n    key: |\n"
        f"{indented_key}\n"
        "decision_logs:\n  console: false\n"
    )
