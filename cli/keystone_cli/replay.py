"""`keystone replay <decision-id> --bundle B --input I` (Ch. 45): re-evaluate a recorded decision.

The audit record keeps `input_hash`, not the policy input (claims stay out of the chain beyond
what the decision needs), so the operator supplies the input — from OPA's decision log or an
incident capture — and replay first proves it is the exact input that was decided on by
recomputing its JCS SHA-256. The bundle's revision is proven against its policy sources
(`inspect_bundle`), so a revision equal to the recorded `policy_digest` means the very policy
that decided; it is evaluated locally with `opa eval` (argv list, no shell) and every decision
field is compared to the record. Same digest: a reproduction. A different one: a counterfactual
("what would this policy have decided?"). Exit 0 when the decisions agree, 1 when they differ.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from typing import IO, Any

from pydantic import ValidationError

from keystone.authz.bundles import BundleError, inspect_bundle
from keystone.authz.evaluator import Decision, DecisionMalformed, PolicyInput, validate_decision
from keystone_cli.client import AdminClient, UsageError
from keystone_cli.output import write_json, write_table

OPA_BIN_ENV = "KEYSTONE_OPA_BIN"
DECISION_QUERY = "data.keystone.authz.decision"
OPA_EVAL_TIMEOUT_SECONDS = 30
_DECISION_TYPES = ("decision_allowed", "decision_denied")
_COMPARED = ("allow", "rule_path", "deny_reasons", "ttl_cap_seconds", "session_policy_ref")


def _recorded(client: AdminClient, decision_id: str) -> dict[str, Any]:
    body = client.request("GET", f"/v1/decisions/{decision_id}")
    for item in body["events"]:
        if item.get("event_type") in _DECISION_TYPES:
            event: dict[str, Any] = item["event"]
            return event
    raise UsageError(f"decision {decision_id} has no decision event to replay")


def _load_input(path: str) -> PolicyInput:
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        return PolicyInput.model_validate(raw)
    except (OSError, ValueError, ValidationError) as exc:
        raise UsageError(f"cannot read policy input {path}: {type(exc).__name__}") from exc


def _opa_binary() -> str:
    configured = os.environ.get(OPA_BIN_ENV)
    found = configured or shutil.which("opa")
    if not found:
        raise UsageError(f"opa binary not found (set {OPA_BIN_ENV} or put opa on PATH)")
    return found


def evaluate(bundle_path: str, policy_input: PolicyInput) -> Decision:
    argv = [_opa_binary(), "eval", "--format", "json", "--bundle", bundle_path, "--stdin-input"]
    argv.append(DECISION_QUERY)
    try:
        completed = subprocess.run(  # noqa: S603 — fixed argv, no shell, operator-run tool
            argv,
            input=json.dumps(policy_input.model_dump(by_alias=True)),
            capture_output=True,
            text=True,
            timeout=OPA_EVAL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UsageError(f"opa eval failed to run: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        first = (completed.stderr.strip().splitlines() or ["no output"])[0]
        raise UsageError(f"opa eval rejected the bundle: {first[:200]}")
    try:
        value = json.loads(completed.stdout)["result"][0]["expressions"][0]["value"]
        return validate_decision(value)
    except (ValueError, KeyError, IndexError, TypeError, DecisionMalformed) as exc:
        raise UsageError("opa eval returned no decision for the input") from exc


def cmd_replay(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    recorded = _recorded(client, args.decision_id)
    policy_input = _load_input(args.input)
    if policy_input.input_hash() != recorded.get("input_hash"):
        raise UsageError(
            "the supplied input is not the one this decision was made on (input_hash differs)"
        )
    try:
        with open(args.bundle, "rb") as handle:
            manifest = inspect_bundle(handle.read())
    except OSError as exc:
        raise UsageError(f"cannot read bundle {args.bundle}: {exc.strerror}") from exc
    except BundleError as exc:
        raise UsageError(f"not a Keystone bundle: {exc}") from exc

    replayed = evaluate(args.bundle, policy_input)
    data = recorded.get("data") or {}
    was = {
        "allow": recorded.get("event_type") == "decision_allowed",
        "rule_path": data.get("rule_path"),
        "deny_reasons": data.get("deny_reasons"),
        "ttl_cap_seconds": data.get("ttl_cap_seconds"),
        "session_policy_ref": data.get("session_policy_ref"),
    }
    now = {field: getattr(replayed, field) for field in _COMPARED}
    rows = [
        {"field": f, "recorded": was[f], "replayed": now[f], "match": was[f] == now[f]}
        for f in _COMPARED
    ]
    same_policy = manifest.revision == recorded.get("policy_digest")
    agree = all(r["match"] for r in rows)
    if args.json:
        write_json(
            out,
            {
                "decision_id": args.decision_id,
                "mode": "reproduction" if same_policy else "counterfactual",
                "recorded_policy_digest": recorded.get("policy_digest"),
                "bundle_digest": manifest.revision,
                "agree": agree,
                "fields": rows,
            },
        )
    else:
        mode = "reproduction (same bundle)" if same_policy else "counterfactual (different bundle)"
        out.write(f"replay of {args.decision_id}: {mode}\n")
        write_table(out, rows, ("field", "recorded", "replayed", "match"))
        out.write("decisions agree\n" if agree else "DECISIONS DIFFER\n")
    return 0 if agree else 1


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    replay = sub.add_parser("replay", help="re-evaluate a recorded decision against a bundle")
    replay.add_argument("decision_id")
    replay.add_argument("--bundle", required=True, help="signed policy bundle .tar.gz")
    replay.add_argument("--input", required=True, help="the decision's policy input (JSON)")
    replay.add_argument("--json", action="store_true")
    replay.set_defaults(admin_handler=cmd_replay)
