"""Policy bundle build/inspect helpers (Ch. 20/21, R8).

The bundle's `revision` IS its digest: sha256 over the policy sources (sorted path + bytes,
tests excluded). CI stamps `metadata.bundle_sequence` (never author- or admin-supplied) and OPA
verifies the bundle's own signature (`opa build --signing-key`) before loading it, so an
unsigned or relabelled bundle can neither be served to OPA nor pinned.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

from keystone.authz.policy_verify.loader import find_opa

DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class BundleError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class BundleManifest:
    revision: str
    bundle_sequence: int
    roots: tuple[str, ...]


def policy_source_digest(root: Path) -> str:
    hasher = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*.rego") if not p.name.endswith("_test.rego")):
        rel = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        hasher.update(len(rel).to_bytes(4, "big") + rel + len(data).to_bytes(8, "big") + data)
    return "sha256:" + hasher.hexdigest()


def build_signed_bundle(
    policies_dir: Path, *, bundle_sequence: int, signing_key_pem: Path, signing_alg: str = "RS256"
) -> bytes:
    """`opa build` with the content digest as revision, the CI sequence in metadata, OPA-signed."""
    if bundle_sequence < 0:
        raise BundleError("bundle_sequence must be a non-negative CI counter")
    revision = policy_source_digest(policies_dir)
    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp) / "src"
        staged.mkdir()
        for path in policies_dir.rglob("*.rego"):
            if path.name.endswith("_test.rego"):
                continue
            target = staged / path.relative_to(policies_dir)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
        manifest_path = policies_dir / ".manifest"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
        manifest["revision"] = revision
        manifest.setdefault("metadata", {})["bundle_sequence"] = bundle_sequence
        (staged / ".manifest").write_text(json.dumps(manifest, separators=(",", ":")))
        out = Path(tmp) / "bundle.tar.gz"
        completed = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [
                find_opa(),
                "build",
                "-b",
                ".",
                "-o",
                str(out),
                "--signing-key",
                str(signing_key_pem),
                "--signing-alg",
                signing_alg,
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=staged,  # member names are recorded relative to the build root
        )
        if completed.returncode != 0:
            raise BundleError(completed.stderr.strip() or "opa build failed")
        return out.read_bytes()


def inspect_bundle(bundle: bytes) -> BundleManifest:
    """Read the manifest and prove the revision matches the sources actually inside the tar."""
    try:
        archive = tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz")
    except tarfile.TarError as exc:
        raise BundleError("not a gzip tarball") from exc
    with archive:
        members = {m.name.lstrip("/").removeprefix("./"): m for m in archive.getmembers()}
        if ".manifest" not in members:
            raise BundleError("bundle has no .manifest")
        if ".signatures.json" not in members:
            raise BundleError("bundle is not signed")
        manifest_file = archive.extractfile(members[".manifest"])
        assert manifest_file is not None
        manifest = json.loads(manifest_file.read())
        revision = manifest.get("revision")
        sequence = (manifest.get("metadata") or {}).get("bundle_sequence")
        if not isinstance(revision, str) or not DIGEST_PATTERN.match(revision):
            raise BundleError("manifest revision is not a sha256 digest")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise BundleError("manifest metadata.bundle_sequence missing (R8: CI must stamp it)")
        roots = tuple(str(r) for r in manifest.get("roots", []))
        # `opa build -b <path>` records members under <path>; hash them relative to the bundle
        # roots so a bundle built in CI and one built here digest identically.
        relative: dict[str, str] = {}
        for name in members:
            if not name.endswith(".rego"):
                continue
            segments = name.split("/")
            rel = name
            for root in roots:
                root_segments = root.split("/")
                for i in range(len(segments)):
                    if segments[i : i + len(root_segments)] == root_segments:
                        rel = "/".join(segments[i:])
                        break
                else:
                    continue
                break
            relative[rel] = name
        hasher = hashlib.sha256()
        for rel in sorted(relative):
            file = archive.extractfile(members[relative[rel]])
            assert file is not None
            data = file.read()
            rel_bytes = rel.encode("utf-8")
            hasher.update(
                len(rel_bytes).to_bytes(4, "big") + rel_bytes + len(data).to_bytes(8, "big") + data
            )
        if "sha256:" + hasher.hexdigest() != revision:
            raise BundleError("manifest revision does not match the policy sources in the bundle")
    return BundleManifest(revision=revision, bundle_sequence=sequence, roots=roots)
