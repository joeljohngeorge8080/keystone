"""`keystone-policy-verify BUNDLE_DIR` — required, non-skippable CI stage before bundle signing."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import IO

from keystone.authz.policy_verify.loader import BundleLoadError, load_bundle
from keystone.authz.policy_verify.validator import DEFAULT_ENTRY, validate


def main(argv: Sequence[str] | None = None, out: IO[str] | None = None) -> int:
    out = sys.stdout if out is None else out
    parser = argparse.ArgumentParser(prog="keystone-policy-verify")
    parser.add_argument("bundle", help="directory containing the policy bundle (.rego files)")
    parser.add_argument("--entry", default=".".join(DEFAULT_ENTRY), help="decision rule path")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        bundle = load_bundle(Path(args.bundle))
    except BundleLoadError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    report = validate(bundle, tuple(args.entry.split(".")))
    if args.json:
        out.write(json.dumps(dataclasses.asdict(report), default=str) + "\n")
    elif report.ok:
        out.write(
            f"OK: {len(report.reachable)} rules reachable from {report.entry}, no violations\n"
        )
    else:
        out.write(f"REJECTED: {len(report.findings)} violation(s) reachable from {report.entry}\n")
        for finding in report.findings:
            out.write(f"  {finding.render()}\n")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
