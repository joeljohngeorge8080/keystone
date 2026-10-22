"""CI entry point: build the OPA-signed policy bundle that the admin plane will accept (R8).

    python -m keystone.authz.build_bundle --policies policies --sequence "$GITHUB_RUN_NUMBER" \
        --signing-key "$RUNNER_TEMP/opa-signing.pem" --out keystone-policy-bundle.tar.gz

The revision is the content digest of the policy sources and the sequence is the CI counter;
the result is inspected exactly as `POST /v1/policy/pins` will inspect it, so a bundle the
admin plane would refuse fails the pipeline instead of the pin.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from keystone.authz.bundles import BundleError, build_signed_bundle, inspect_bundle


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m keystone.authz.build_bundle")
    parser.add_argument("--policies", required=True, type=Path)
    parser.add_argument("--sequence", required=True, type=int, help="CI-assigned run counter")
    parser.add_argument("--signing-key", required=True, type=Path, help="OPA bundle signing key")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        bundle = build_signed_bundle(
            args.policies, bundle_sequence=args.sequence, signing_key_pem=args.signing_key
        )
        manifest = inspect_bundle(bundle)
    except BundleError as exc:
        sys.stderr.write(f"build_bundle: {exc}\n")
        return 1
    args.out.write_bytes(bundle)
    sys.stdout.write(f"{manifest.revision} sequence={manifest.bundle_sequence}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
