"""Auto-generated hostile matrix (R2): required, with the structural validator, before signing.

    python -m keystone.authz.policy_verify.hostile policies --seeds tests/policy/hostile_seeds.json

Seeds are policy inputs that a grant ALLOWS, at least one per grant package (a grant without a
seed fails the run, so coverage cannot silently lapse). From every seed the matrix derives, for
each `input.identity.<claim>` the policy references: the claim absent, and the claim as every
wrong JSON type; plus fork, wrong-organisation, mutated-ref and near-miss repository
permutations. Every derived input must be denied. All cases are decided in one `opa eval`.
Exit 0: all denied; 1: a hostile input was allowed; 2: bad seeds or tooling failure.
"""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from keystone.authz.policy_verify.loader import BundleLoadError, _run_opa, find_opa

DECISION = "data.keystone.authz.decision"
GRANTS_PREFIX = ("keystone", "grants")
WRONG_TYPES: tuple[tuple[str, Any], ...] = (
    ("number", 7),
    ("bool", True),
    ("list", ["x"]),
    ("object", {"x": "y"}),
    ("null", None),
)
FORK_EVENTS = ("pull_request", "pull_request_target")
REF_MUTATIONS: tuple[tuple[str, str], ...] = (
    ("suffix", "{v}-evil"),
    ("child", "{v}/evil"),
    ("tag", "refs/tags/{leaf}"),
    ("upper", "{upper}"),
    ("space", "{v} "),
    ("nul", "{v}\u0000"),
    ("traversal", "refs/heads/evil/../{leaf}"),
)


_ABSENT = object()  # sentinel: remove the claim instead of setting it


@dataclass(frozen=True)
class Case:
    seed: str
    name: str
    input: dict[str, Any]


def _walk(node: Any) -> Iterator[Any]:
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def _rego_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.rego") if not p.name.endswith("_test.rego"))


def referenced_claims(root: Path) -> set[str]:
    """Every `input.identity.<claim>` read anywhere in the bundle's non-test modules."""
    claims: set[str] = set()
    for path in _rego_files(root):
        for node in _walk(json.loads(_run_opa(["parse", "--format", "json", str(path)]))):
            if not (isinstance(node, dict) and node.get("type") == "ref"):
                continue
            terms = node.get("value")
            if (
                isinstance(terms, list)
                and len(terms) >= 3
                and terms[0] == {"type": "var", "value": "input"}
                and terms[1] == {"type": "string", "value": "identity"}
                and terms[2].get("type") == "string"
            ):
                claims.add(str(terms[2]["value"]))
    return claims


def grant_packages(root: Path) -> set[str]:
    """Names of every `package keystone.grants.<name>` (in decision form, `_` -> `-`)."""
    names: set[str] = set()
    for path in _rego_files(root):
        package = json.loads(_run_opa(["parse", "--format", "json", str(path)]))["package"]
        segments = tuple(str(s["value"]) for s in package["path"][1:])
        if segments[:2] == GRANTS_PREFIX and len(segments) == 3:
            names.add(segments[2].replace("_", "-"))
    return names


def _with(seed: dict[str, Any], **identity: Any) -> dict[str, Any]:
    mutated = copy.deepcopy(seed)
    for claim, value in identity.items():
        if value is _ABSENT:
            mutated["identity"].pop(claim, None)
        else:
            mutated["identity"][claim] = value
    return mutated


def cases_for(seed_name: str, seed: dict[str, Any], claims: set[str]) -> list[Case]:
    identity: dict[str, Any] = seed["identity"]
    out: list[Case] = []
    for claim in sorted(claims & identity.keys()):
        out.append(Case(seed_name, f"{claim}: absent", _with(seed, **{claim: _ABSENT})))
        for label, wrong in WRONG_TYPES:
            out.append(Case(seed_name, f"{claim}: {label}", _with(seed, **{claim: wrong})))
    if "event_name" in identity:
        for event in FORK_EVENTS:
            fork = _with(seed, event_name=event, head_ref="refs/heads/attacker")
            out.append(Case(seed_name, f"fork: event_name={event}", fork))
    if "repository_owner" in identity:
        name = str(identity.get("repository", "x/app")).split("/", 1)[-1]
        out.append(
            Case(
                seed_name,
                "wrong org",
                _with(
                    seed,
                    repository_owner="evil-org",
                    repository=f"evil-org/{name}",
                    sub=f"repo:evil-org/{name}:ref:{identity.get('ref', '')}",
                ),
            )
        )
    if isinstance(identity.get("ref"), str):
        ref: str = identity["ref"]
        leaf = ref.rsplit("/", 1)[-1]
        for label, template in REF_MUTATIONS:
            value = template.format(v=ref, leaf=leaf, upper=ref.upper())
            if value != ref:
                out.append(Case(seed_name, f"mutated ref: {label}", _with(seed, ref=value)))
    if isinstance(identity.get("repository"), str):
        repo: str = identity["repository"]
        for label, value in (
            ("case", repo.upper()),
            ("suffix", repo + "-fork"),
            ("prefix", "x" + repo),
        ):
            out.append(
                Case(seed_name, f"near-miss repository: {label}", _with(seed, repository=value))
            )
    if isinstance(identity.get("repository_id"), str):
        rid: str = identity["repository_id"]
        for label, value in (
            ("leading zero", "0" + rid),
            ("padded", rid + " "),
            ("other", rid + "1"),
        ):
            out.append(
                Case(
                    seed_name, f"near-miss repository_id: {label}", _with(seed, repository_id=value)
                )
            )
    return out


def evaluate(root: Path, inputs: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Decide every input in one `opa eval`, against the bundle's own entry point."""
    query = f"[d | some c in input.cases; d := {DECISION} with input as c]"
    payload = json.dumps({"cases": list(inputs)})
    completed = _run_opa_stdin(
        ["eval", "--format", "json", "-b", str(root), "--stdin-input", query], payload
    )
    result = json.loads(completed)["result"][0]["expressions"][0]["value"]
    if not isinstance(result, list) or len(result) != len(inputs):
        raise BundleLoadError("opa eval did not return one decision per case")
    return result


def _run_opa_stdin(args: list[str], stdin: str) -> str:
    completed = subprocess.run(  # noqa: S603 — fixed argv list, no shell
        [find_opa(), *args], input=stdin, capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise BundleLoadError((completed.stderr or completed.stdout).strip())
    return completed.stdout


def run(root: Path, seeds_path: Path, out: IO[str]) -> int:
    seeds: list[dict[str, Any]] = json.loads(seeds_path.read_text(encoding="utf-8"))
    claims = referenced_claims(root)
    baseline = evaluate(root, [s["input"] for s in seeds])
    allowed_grants = set()
    for seed, decision in zip(seeds, baseline, strict=True):
        if decision.get("allow") is not True:
            out.write(f"SEED NOT ALLOWED: {seed['name']} -> {decision.get('deny_reasons')}\n")
            return 2
        allowed_grants.add(str(decision.get("grant", "")).replace("_", "-"))
    uncovered = grant_packages(root) - allowed_grants
    if uncovered:
        out.write(f"GRANTS WITHOUT A SEED: {', '.join(sorted(uncovered))}\n")
        return 2
    cases = [c for seed in seeds for c in cases_for(seed["name"], seed["input"], claims)]
    decisions = evaluate(root, [c.input for c in cases])
    allowed = [c for c, d in zip(cases, decisions, strict=True) if d.get("allow") is not False]
    for case in allowed:
        out.write(f"HOSTILE INPUT ALLOWED: {case.seed}: {case.name}\n")
    out.write(
        f"hostile matrix: {len(cases)} cases over {len(seeds)} seeds and {len(claims)} claims "
        f"({', '.join(sorted(claims))}); {len(allowed)} allowed\n"
    )
    return 1 if allowed else 0


def main(argv: Sequence[str] | None = None, out: IO[str] | None = None) -> int:
    out = sys.stdout if out is None else out
    parser = argparse.ArgumentParser(prog="python -m keystone.authz.policy_verify.hostile")
    parser.add_argument("root", type=Path, help="policy bundle directory")
    parser.add_argument("--seeds", required=True, type=Path, help="JSON list of {name, input}")
    args = parser.parse_args(argv)
    try:
        return run(args.root, args.seeds, out)
    except (BundleLoadError, OSError, ValueError, KeyError) as exc:
        sys.stderr.write(f"hostile matrix: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
