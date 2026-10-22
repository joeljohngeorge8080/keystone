"""Render the OPA sidecar's config file (deployment init step; Ch. 21, R5).

    python -m keystone.admin.opa_config --bundle-url http://127.0.0.1:8081 \
        --public-key /run/secrets/opa_bundle_public_key \
        --token-env KEYSTONE_BUNDLE_SERVICE_TOKEN --out /config/opa.yaml

Every argument is a URL, a path or a variable name, never a secret: OPA expands the token from
its own environment when it loads the config (`--token-env`), or reads it from a file
(`--token-path`), so the bundle-service bearer never lands in the rendered file.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from keystone.admin.app import BUNDLE_PATH
from keystone.authz.pins import opa_config_yaml


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m keystone.admin.opa_config")
    parser.add_argument("--bundle-url", required=True, help="the admin plane, as OPA reaches it")
    parser.add_argument("--public-key", required=True, type=Path, help="bundle-signing public key")
    token = parser.add_mutually_exclusive_group(required=True)
    token.add_argument("--token-env", help="variable holding the bundle-service bearer, for OPA")
    token.add_argument("--token-path", help="file holding the bundle-service bearer, for OPA")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--poll-seconds", type=int, default=5)
    args = parser.parse_args(argv)
    try:
        pem = args.public_key.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        sys.stderr.write(f"opa_config: cannot read the public key: {exc}\n")
        return 2
    if "PUBLIC KEY-----" not in pem or "PRIVATE" in pem:
        sys.stderr.write("opa_config: --public-key must be a PEM public key\n")
        return 2
    try:
        rendered = opa_config_yaml(
            bundle_service_url=args.bundle_url,
            resource=BUNDLE_PATH.lstrip("/"),
            verification_key_pem=pem,
            poll_seconds=args.poll_seconds,
            bearer_token_path=args.token_path,
            bearer_token_env=args.token_env,
        )
    except ValueError as exc:
        sys.stderr.write(f"opa_config: {exc}\n")
        return 2
    args.out.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
