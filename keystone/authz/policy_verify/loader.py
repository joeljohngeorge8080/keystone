"""Load a policy bundle into OPA's own AST (via `opa parse`) — never a second Rego parser."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

Term = dict[str, Any]
Expr = dict[str, Any]
RulePath = tuple[str, ...]

OPA_BIN_ENV = "KEYSTONE_OPA_BIN"


class BundleLoadError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Location:
    file: str
    row: int
    col: int

    def __str__(self) -> str:
        return f"{self.file}:{self.row}:{self.col}"


@dataclass(slots=True)
class Rule:
    path: RulePath
    file: str
    head: dict[str, Any]
    body: list[Expr]
    is_default: bool
    else_chain: list[dict[str, Any]] = field(default_factory=list)
    location: Location | None = None

    @property
    def name(self) -> str:
        return self.path[-1]

    @property
    def dotted(self) -> str:
        return ".".join(self.path)


@dataclass(slots=True)
class Module:
    file: str
    package: RulePath
    imports: dict[str, RulePath]
    rules: list[Rule]


@dataclass(slots=True)
class Bundle:
    root: Path
    modules: list[Module]

    def rules_by_path(self) -> dict[RulePath, list[Rule]]:
        grouped: dict[RulePath, list[Rule]] = {}
        for module in self.modules:
            for rule in module.rules:
                grouped.setdefault(rule.path, []).append(rule)
        return grouped


def find_opa() -> str:
    configured = os.environ.get(OPA_BIN_ENV)
    if configured:
        return configured
    found = shutil.which("opa")
    if found is None:
        raise BundleLoadError(f"opa binary not found on PATH (or set {OPA_BIN_ENV})")
    return found


def _run_opa(args: list[str]) -> str:
    completed = subprocess.run(  # noqa: S603 — fixed argv list, no shell, opa path resolved above
        [find_opa(), *args], capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise BundleLoadError((completed.stderr or completed.stdout).strip())
    return completed.stdout


def _path_of_ref(node: Term | list[Term]) -> RulePath:
    """`package.path` is a bare segment list; an import path is a ref term wrapping one."""
    raw_segments = node["value"] if isinstance(node, dict) else node
    segments: list[str] = []
    for segment in raw_segments:
        if segment["type"] not in {"var", "string"}:
            raise BundleLoadError(f"unsupported package/import path segment: {segment}")
        segments.append(str(segment["value"]))
    return tuple(segments)


def _location(node: dict[str, Any], file: str) -> Location | None:
    loc = node.get("location")
    if not loc:
        return None
    return Location(file=file, row=int(loc.get("row", 0)), col=int(loc.get("col", 0)))


def _rule_from_json(raw: dict[str, Any], package: RulePath, file: str) -> Rule:
    head = raw["head"]
    ref = head.get("ref") or [{"type": "var", "value": head["name"]}]
    name_segments: list[str] = []
    for segment in ref:
        if segment["type"] == "var" and not name_segments:
            name_segments.append(str(segment["value"]))
        elif segment["type"] == "string":
            name_segments.append(str(segment["value"]))
        else:
            break  # dynamic head segments (rare) — keep the static prefix as the rule path
    else_chain: list[dict[str, Any]] = []
    cursor = raw.get("else")
    while cursor:
        else_chain.append(cursor)
        cursor = cursor.get("else")
    return Rule(
        path=(*package, *name_segments),
        file=file,
        head=head,
        body=list(raw.get("body") or []),
        is_default=bool(raw.get("default")),
        else_chain=else_chain,
        location=_location(raw, file),
    )


def parse_module(file: Path, root: Path) -> Module:
    raw = json.loads(
        _run_opa(["parse", "--format", "json", "--json-include", "locations", str(file)])
    )
    package = _path_of_ref(raw["package"]["path"])
    imports: dict[str, RulePath] = {}
    for imp in raw.get("imports") or []:
        path = _path_of_ref(imp["path"])
        alias = str(imp.get("alias") or path[-1])
        imports[alias] = path
    rel = str(file.relative_to(root))
    rules = [_rule_from_json(r, package, rel) for r in raw.get("rules") or []]
    return Module(file=rel, package=package, imports=imports, rules=rules)


def load_bundle(root: Path) -> Bundle:
    if not root.is_dir():
        raise BundleLoadError(f"{root} is not a directory")
    _run_opa(["check", "--strict", str(root)])
    files = sorted(p for p in root.rglob("*.rego") if not p.name.endswith("_test.rego"))
    if not files:
        raise BundleLoadError(f"no .rego files under {root}")
    return Bundle(root=root, modules=[parse_module(f, root) for f in files])
