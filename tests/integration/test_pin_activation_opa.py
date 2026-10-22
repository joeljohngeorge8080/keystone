"""Two-phase pin activation (R5/R8) against a real OPA polling a Keystone-served signed bundle."""

from __future__ import annotations

import http.server
import io
import json
import shutil
import socket
import subprocess
import tarfile
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import text
from sqlalchemy.engine import Engine

from keystone.audit.events import EventType
from keystone.audit.sink import PostgresAuditSink
from keystone.audit.store import load_events, snapshot_head
from keystone.authz.bundles import (
    BundleError,
    build_signed_bundle,
    inspect_bundle,
    policy_source_digest,
)
from keystone.authz.pins import (
    OpaBundleGateway,
    PinActivator,
    PinSequenceRejected,
    PolicyLoadTimeout,
    StagedBundleStore,
    opa_config_yaml,
    restage_active_bundle,
)
from keystone.authz.service import active_pin

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH"),
]

REPO = Path(__file__).resolve().parents[2]
POLICIES = REPO / "policies"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _rsa_pair(tmp: Path, name: str) -> tuple[Path, str]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp / f"{name}.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_path, public_pem.decode()


@dataclass
class Harness:
    opa_url: str
    store: StagedBundleStore
    signing_key: Path
    other_key: Path
    tmp: Path


@pytest.fixture(scope="module")
def harness(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Harness]:
    tmp = tmp_path_factory.mktemp("pins")
    signing_key, public_pem = _rsa_pair(tmp, "signing")
    other_key, _ = _rsa_pair(tmp, "other")
    store = StagedBundleStore()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            current = store.current()
            if self.path != "/bundles/keystone.tar.gz" or current is None:
                self.send_response(404)
                self.end_headers()
                return
            digest, body = current
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("ETag", digest)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            return

    bundle_port = _free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", bundle_port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    config = tmp / "opa.yaml"
    config.write_text(
        opa_config_yaml(
            bundle_service_url=f"http://127.0.0.1:{bundle_port}",
            resource="bundles/keystone.tar.gz",
            verification_key_pem=public_pem,
            poll_seconds=1,
        )
    )
    opa_port = _free_port()
    proc = subprocess.Popen(
        [
            "opa",
            "run",
            "--server",
            "--addr",
            f"127.0.0.1:{opa_port}",
            "--log-level",
            "error",
            "-c",
            str(config),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    opa_url = f"http://127.0.0.1:{opa_port}"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if httpx.get(opa_url + "/health", timeout=0.5).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    else:
        proc.kill()
        raise RuntimeError("opa did not start")
    yield Harness(
        opa_url=opa_url, store=store, signing_key=signing_key, other_key=other_key, tmp=tmp
    )
    proc.kill()
    proc.wait()
    server.shutdown()


def _variant_policies(tmp: Path, name: str, marker: str) -> Path:
    target = tmp / name
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(POLICIES, target)
    grant = target / "keystone" / "grants" / "deploy_prod.rego"
    grant.write_text(
        grant.read_text().replace("ttl_cap_seconds := 900", f"ttl_cap_seconds := {marker}")
    )
    return target


def _activator(engine: Engine, harness: Harness, timeout: float = 15.0) -> PinActivator:
    gateway = OpaBundleGateway(harness.store, harness.opa_url)
    return PinActivator(
        engine,
        PostgresAuditSink(),
        gateway,
        load_timeout_seconds=timeout,
        poll_interval_seconds=0.2,
    )


def _audit_types(engine: Engine) -> list[str]:
    with engine.connect() as conn:
        head = snapshot_head(conn)
        return [e.event_type for e in load_events(conn, 1, head.seq)]


def test_two_phase_activation_rollback_and_rejections(app_engine: Engine, harness: Harness) -> None:
    activator = _activator(app_engine, harness)
    bundle_a = build_signed_bundle(POLICIES, bundle_sequence=1, signing_key_pem=harness.signing_key)
    manifest_a = inspect_bundle(bundle_a)
    assert manifest_a.revision == policy_source_digest(POLICIES) and manifest_a.bundle_sequence == 1

    with app_engine.connect() as conn:
        assert active_pin(conn) is None
    result = activator.activate(bundle_a, pinned_by=None, actor="admin:alice")
    assert result.pin.bundle_digest == manifest_a.revision and not result.rolled_back
    loaded = httpx.get(harness.opa_url + "/v1/data/system/bundles").json()["result"]
    assert loaded["keystone"]["manifest"]["revision"] == manifest_a.revision  # OPA confirmed first
    with app_engine.connect() as conn:
        pin = active_pin(conn)
        assert (
            pin is not None
            and pin.bundle_digest == manifest_a.revision
            and pin.bundle_sequence == 1
        )
        rows = conn.execute(text("SELECT count(*) FROM policy_pins")).scalar_one()
    assert rows == 1
    assert _audit_types(app_engine) == [EventType.ADMIN_POLICY_PINNED.value]

    # Idempotent re-activation of the live bundle: no new row, but still audited.
    activator.activate(bundle_a, pinned_by=None, actor="admin:alice")
    with app_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM policy_pins")).scalar_one() == 1

    # Forward pin to sequence 2 with different content.
    policies_b = _variant_policies(harness.tmp, "policies_b", "1200")
    bundle_b = build_signed_bundle(
        policies_b, bundle_sequence=2, signing_key_pem=harness.signing_key
    )
    manifest_b = inspect_bundle(bundle_b)
    assert manifest_b.revision != manifest_a.revision
    activator.activate(bundle_b, pinned_by=None, actor="admin:alice")
    with app_engine.connect() as conn:
        pin = active_pin(conn)
        assert pin is not None and pin.bundle_sequence == 2
        active_rows = conn.execute(
            text("SELECT count(*) FROM policy_pins WHERE active")
        ).scalar_one()
    assert active_rows == 1

    # Rollback without force is refused BEFORE staging: OPA keeps B.
    with pytest.raises(PinSequenceRejected):
        activator.activate(bundle_a, pinned_by=None, actor="admin:mallory")
    loaded = httpx.get(harness.opa_url + "/v1/data/system/bundles").json()["result"]
    assert loaded["keystone"]["manifest"]["revision"] == manifest_b.revision

    # Forced rollback: loads A, pins A, loud audit event.
    result = activator.activate(bundle_a, pinned_by=None, actor="admin:alice", force_rollback=True)
    assert result.rolled_back is True
    with app_engine.connect() as conn:
        pin = active_pin(conn)
        assert pin is not None and pin.bundle_digest == manifest_a.revision
        forced = conn.execute(
            text("SELECT forced_rollback FROM policy_pins WHERE active")
        ).scalar_one()
    assert forced is True
    assert _audit_types(app_engine)[-1] == EventType.ADMIN_POLICY_ROLLBACK.value

    # A bundle signed with a key OPA does not trust never loads: timeout, pin unchanged.
    policies_c = _variant_policies(harness.tmp, "policies_c", "1500")
    bundle_c = build_signed_bundle(policies_c, bundle_sequence=3, signing_key_pem=harness.other_key)
    quick = _activator(app_engine, harness, timeout=3.0)
    with pytest.raises(PolicyLoadTimeout):
        quick.activate(bundle_c, pinned_by=None, actor="admin:alice")
    with app_engine.connect() as conn:
        pin = active_pin(conn)
        assert pin is not None and pin.bundle_digest == manifest_a.revision
    loaded = httpx.get(harness.opa_url + "/v1/data/system/bundles").json()["result"]
    assert loaded["keystone"]["manifest"]["revision"] == manifest_a.revision


def test_restarted_admin_plane_restages_the_active_pins_bundle(
    app_engine: Engine, admin_engine: Engine, harness: Harness
) -> None:
    assert restage_active_bundle(app_engine, StagedBundleStore()) is None  # nothing pinned yet
    bundle = build_signed_bundle(POLICIES, bundle_sequence=1, signing_key_pem=harness.signing_key)
    result = _activator(app_engine, harness).activate(bundle, pinned_by=None, actor="admin:alice")

    after_restart = StagedBundleStore()  # a fresh process: the in-memory stage is empty
    assert restage_active_bundle(app_engine, after_restart) == result.pin.bundle_digest
    assert after_restart.current() == (result.pin.bundle_digest, bundle)

    # Persisted bytes are append-only: a digest's bundle can be neither rewritten nor removed.
    with pytest.raises(Exception, match="append-only"), admin_engine.begin() as conn:
        conn.execute(text("UPDATE policy_bundles SET bundle = '\\x00'"))
    with pytest.raises(Exception, match="append-only"), admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM policy_bundles"))


def test_restage_refuses_bytes_that_do_not_prove_the_pinned_revision(
    app_engine: Engine, admin_engine: Engine, harness: Harness
) -> None:
    # A pin whose persisted bytes are a different (validly signed) bundle is never served.
    other = build_signed_bundle(
        _variant_policies(harness.tmp, "policies_r", "1300"),
        bundle_sequence=1,
        signing_key_pem=harness.signing_key,
    )
    pinned = policy_source_digest(POLICIES)
    with admin_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO policy_bundles (digest, bundle) VALUES (:d, :b)"),
            {"d": pinned, "b": other},
        )
        conn.execute(
            text(
                "INSERT INTO policy_pins (id, bundle_digest, bundle_sequence, active) "
                "VALUES (gen_random_uuid(), :d, 1, true)"
            ),
            {"d": pinned},
        )
    store = StagedBundleStore()
    with pytest.raises(BundleError, match="does not match the active pin"):
        restage_active_bundle(app_engine, store)
    assert store.current() is None


def test_bundle_inspection_refuses_unsigned_relabelled_or_unsequenced(
    harness: Harness, tmp_path: Path
) -> None:
    unsigned = tmp_path / "unsigned.tar.gz"
    subprocess.run(
        [
            "opa",
            "build",
            "-b",
            str(POLICIES),
            "--ignore",
            "*_test.rego",
            "-r",
            policy_source_digest(POLICIES),
            "-o",
            str(unsigned),
        ],
        check=True,
        capture_output=True,
    )
    with pytest.raises(BundleError, match="not signed"):
        inspect_bundle(unsigned.read_bytes())

    good = build_signed_bundle(POLICIES, bundle_sequence=5, signing_key_pem=harness.signing_key)

    def rewrite_manifest(bundle: bytes, mutate: dict[str, object]) -> bytes:
        out = io.BytesIO()
        with (
            tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as src,
            tarfile.open(fileobj=out, mode="w:gz") as dst,
        ):
            for member in src.getmembers():
                file = src.extractfile(member)
                data = file.read() if file else b""
                if member.name.endswith(".manifest"):
                    manifest = json.loads(data)
                    manifest.update(mutate)
                    if "metadata" in mutate and mutate["metadata"] is None:
                        manifest.pop("metadata", None)
                    data = json.dumps(manifest).encode()
                    member.size = len(data)
                dst.addfile(member, io.BytesIO(data))
        return out.getvalue()

    with pytest.raises(BundleError, match="does not match"):
        inspect_bundle(rewrite_manifest(good, {"revision": "sha256:" + "00" * 32}))
    with pytest.raises(BundleError, match="sha256"):
        inspect_bundle(rewrite_manifest(good, {"revision": "v1.2.3"}))
    with pytest.raises(BundleError, match="bundle_sequence"):
        inspect_bundle(rewrite_manifest(good, {"metadata": None}))
    with pytest.raises(BundleError):
        inspect_bundle(b"not a tarball")
    with pytest.raises(BundleError):
        build_signed_bundle(POLICIES, bundle_sequence=-1, signing_key_pem=harness.signing_key)
