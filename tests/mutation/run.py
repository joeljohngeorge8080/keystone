"""Mutation testing for the audit chain and verifier (spec Ch. 57: "mutation testing on chain +
verifier"). Standard library only.

    uv run python -m tests.mutation.run            # report + exit 1 below the threshold
    uv run python -m tests.mutation.run --list     # show every mutant without running

Every mutation point in the target modules (comparison and boolean operators, arithmetic,
constants, `not`, early-return guards, slice/length arithmetic) is applied one at a time. The
mutant module is compiled from the mutated AST and installed in `sys.modules` under its real
name BEFORE pytest imports anything, so every importer — tests and production code alike —
gets the mutant. A mutant is killed when the suite fails or times out; a survivor is a test gap.
"""

from __future__ import annotations

import argparse
import ast
import copy
import os
import subprocess
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    "keystone.audit.chain",
    "keystone.audit.verify",
    "keystone.audit.canonical",
)
TESTS = (
    "tests/unit/test_chain.py",
    "tests/unit/test_verify.py",
    "tests/unit/test_json_equal.py",
    "tests/unit/test_canonical.py",
    "tests/unit/test_events.py",
)
DEFAULT_THRESHOLD = 0.95
# Mutants proven not to change behaviour, with the reason. Keyed by (module, line, description).
EQUIVALENT: dict[tuple[str, int, str], str] = {
    ("keystone.audit.verify", 80, "True -> False"): (
        "zip(strict=...) runs only after len(a) == len(b) has been checked on the same line"
    ),
}
TIMEOUT_SECONDS = 60

_COMPARE_SWAPS: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
}
_BINOP_SWAPS: dict[type[ast.operator], type[ast.operator]] = {
    ast.Add: ast.Sub,
    ast.Sub: ast.Add,
    ast.Mult: ast.FloorDiv,
}


@dataclass(frozen=True)
class Mutant:
    module: str
    index: int  # the n-th mutation point in the module, in AST walk order
    line: int
    description: str


def _decorator_nodes(tree: ast.Module) -> set[int]:
    # Decorator arguments (`@dataclass(frozen=True, slots=True)`) configure the class, not the
    # logic under test; mutating them yields equivalent or untestable mutants.
    inside: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.ClassDef):
            for decorator in node.decorator_list:
                inside.update(id(n) for n in ast.walk(decorator))
    return inside


def _points(tree: ast.Module) -> Iterator[tuple[ast.AST, int, str]]:
    """Every (node, operator index, description) mutation point, in a deterministic order."""
    skip = _decorator_nodes(tree)
    for node in ast.walk(tree):
        if id(node) in skip:
            continue
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant):
            if node.value.value is None:
                continue  # `return None` -> `return None` is the identity
        if isinstance(node, ast.Compare):
            for i, op in enumerate(node.ops):
                if type(op) in _COMPARE_SWAPS:
                    yield node, i, f"{type(op).__name__} -> {_COMPARE_SWAPS[type(op)].__name__}"
        elif isinstance(node, ast.BoolOp):
            other = "Or" if isinstance(node.op, ast.And) else "And"
            yield node, 0, f"{type(node.op).__name__} -> {other}"
        elif isinstance(node, ast.BinOp) and type(node.op) in _BINOP_SWAPS:
            yield node, 0, f"{type(node.op).__name__} -> {_BINOP_SWAPS[type(node.op)].__name__}"
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            yield node, 0, "drop `not`"
        elif isinstance(node, ast.Constant) and type(node.value) is bool:
            yield node, 0, f"{node.value} -> {not node.value}"
        elif isinstance(node, ast.Constant) and type(node.value) is int:
            yield node, 0, f"{node.value} -> {node.value + 1}"
        elif isinstance(node, ast.If):
            yield node, 0, "if-condition -> False"
        elif isinstance(node, ast.Return) and node.value is not None:
            yield node, 0, "return value -> None"


def _apply(tree: ast.Module, index: int) -> ast.Module:
    mutated = copy.deepcopy(tree)
    node, op_index, _ = list(_points(mutated))[index]
    if isinstance(node, ast.Compare):
        node.ops[op_index] = _COMPARE_SWAPS[type(node.ops[op_index])]()
    elif isinstance(node, ast.BoolOp):
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
    elif isinstance(node, ast.BinOp):
        node.op = _BINOP_SWAPS[type(node.op)]()
    elif isinstance(node, ast.UnaryOp):
        _replace(mutated, node, node.operand)
    elif isinstance(node, ast.Constant) and type(node.value) is bool:
        node.value = not node.value
    elif isinstance(node, ast.Constant) and type(node.value) is int:
        node.value = node.value + 1
    elif isinstance(node, ast.If):
        node.test = ast.Constant(value=False)
    elif isinstance(node, ast.Return):
        node.value = ast.Constant(value=None)
    return ast.fix_missing_locations(mutated)


def _replace(tree: ast.AST, old: ast.AST, new: ast.AST) -> None:
    for parent in ast.walk(tree):
        for field, value in ast.iter_fields(parent):
            if value is old:
                setattr(parent, field, new)
                return
            if isinstance(value, list):
                for i, item in enumerate(value):
                    if item is old:
                        value[i] = new
                        return


def _source_path(module: str) -> Path:
    return ROOT / (module.replace(".", "/") + ".py")


def mutants(modules: Sequence[str] = TARGETS) -> list[Mutant]:
    found = []
    for module in modules:
        tree = ast.parse(_source_path(module).read_text(encoding="utf-8"))
        for index, (node, _, description) in enumerate(_points(tree)):
            line = getattr(node, "lineno", 0)
            if (module, line, description) not in EQUIVALENT:
                found.append(Mutant(module, index, line, description))
    return found


# Runs inside the child interpreter: build the mutant, install it, then run pytest.
_BOOTSTRAP = """
import ast, importlib, sys, types
from tests.mutation.run import _apply, _source_path
module, index, tests = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
path = _source_path(module)
tree = _apply(ast.parse(path.read_text(encoding="utf-8")), index)
parent, _, leaf = module.rpartition(".")
importlib.import_module(parent)
mutant = types.ModuleType(module)
mutant.__file__ = str(path)
sys.modules[module] = mutant
setattr(sys.modules[parent], leaf, mutant)
exec(compile(tree, str(path), "exec"), mutant.__dict__)
import pytest
sys.exit(pytest.main(["-q", "-x", "-p", "no:cacheprovider", *tests]))
"""


def killed(mutant: Mutant, tests: Sequence[str] = TESTS) -> bool:
    try:
        completed = subprocess.run(
            [sys.executable, "-c", _BOOTSTRAP, mutant.module, str(mutant.index), *tests],
            cwd=ROOT,
            capture_output=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except subprocess.TimeoutExpired:
        return True  # an infinite loop is a detected behaviour change
    return completed.returncode != 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tests.mutation.run")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--list", action="store_true", help="list mutants without running")
    args = parser.parse_args(argv)
    every = mutants()
    if args.list:
        for m in every:
            print(f"{m.module}:{m.line}  #{m.index}  {m.description}")
        return 0
    # Baseline: against unmutated code the suite must pass, or every mutant would look killed.
    baseline = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *TESTS],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if baseline.returncode != 0:
        print("baseline suite fails on unmutated code; fix that first")
        return 2
    survivors = []
    for m in every:
        if not killed(m):
            survivors.append(m)
            print(f"SURVIVED  {m.module}:{m.line}  {m.description}", flush=True)
    score = 1 - len(survivors) / len(every)
    print(f"mutation score {score:.1%} ({len(every) - len(survivors)}/{len(every)} killed)")
    return 0 if score >= args.threshold else 1


if __name__ == "__main__":
    raise SystemExit(main())
