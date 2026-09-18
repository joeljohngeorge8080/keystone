"""keystone-policy-verify — structural validator for the positive-assertion-only policy invariant.

Spec Ch. 20 (R2). Computes the transitive call graph reachable from the decision entry point and
rejects, anywhere in that set: negation over input, permissive defaults/else, absence-masking
builtins, unguarded iteration over input collections, and claims used without a presence+type
guard. Rules whose name starts with `deny` are deny-context and exempt (negation belongs there).
"""

from __future__ import annotations

import enum
import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from keystone.authz.policy_verify.loader import Bundle, Expr, Location, Rule, RulePath, Term

DEFAULT_ENTRY: RulePath = ("data", "keystone", "authz", "decision")

TYPE_GUARDS = frozenset({"is_string", "is_boolean", "is_number", "is_object", "is_array", "is_set"})
MASKING_BUILTINS = frozenset({"object.get", "object.union", "object.union_n"})
NON_EMPTY_OPS = frozenset({"gt", "gte", "neq"})
COMPARISON_OPS = frozenset({"equal", "eq", "neq", "gt", "gte", "lt", "lte", "internal.member_2"})
CLAIM_PREFIX: RulePath = ("input", "identity")


class Code(enum.StrEnum):
    MISSING_ENTRY = "MISSING_ENTRY"
    NOT_OVER_INPUT = "NOT_OVER_INPUT"
    PERMISSIVE_DEFAULT = "PERMISSIVE_DEFAULT"
    PERMISSIVE_ELSE = "PERMISSIVE_ELSE"
    MASKING_BUILTIN = "MASKING_BUILTIN"
    UNGUARDED_ITERATION = "UNGUARDED_ITERATION"
    UNGUARDED_CLAIM = "UNGUARDED_CLAIM"
    DENY_WITHOUT_REASON = "DENY_WITHOUT_REASON"
    WITH_OVERRIDE = "WITH_OVERRIDE"


@dataclass(frozen=True, slots=True)
class Finding:
    code: Code
    rule: str
    location: Location | None
    message: str

    def render(self) -> str:
        where = f" ({self.location})" if self.location else ""
        return f"{self.code} {self.rule}{where}: {self.message}"


@dataclass(frozen=True, slots=True)
class Report:
    ok: bool
    entry: str
    reachable: tuple[str, ...]
    findings: tuple[Finding, ...]


# ---------------------------------------------------------------- term utilities


def _strip(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: _strip(v) for k, v in node.items() if k != "location"}
    if isinstance(node, list):
        return [_strip(v) for v in node]
    return node


def _key(term: Term) -> str:
    return json.dumps(_strip(term), sort_keys=True)


def _ref_segments(term: Term) -> list[str | None] | None:
    if term.get("type") != "ref":
        return None
    out: list[str | None] = []
    for i, seg in enumerate(term["value"]):
        if seg["type"] == "var":
            out.append(str(seg["value"]) if i == 0 else None)
        elif seg["type"] == "string":
            out.append(str(seg["value"]))
        else:
            out.append(None)
    return out


def _static_ref(term: Term) -> RulePath | None:
    segs = _ref_segments(term)
    if segs is None or any(s is None for s in segs):
        return None
    return tuple(s for s in segs if s is not None)


def _builtin_name(term: Term) -> str | None:
    """`equal`, `count`, `object.get`, `internal.member_2` — the operator ref of a call form."""
    path = _static_ref(term)
    return None if path is None else ".".join(path)


def _iter_subterms(term: Any) -> Iterator[Term]:
    """Every term nested inside `term`, including comprehension heads (not their bodies)."""
    if not isinstance(term, dict) or "type" not in term:
        return
    yield term
    kind = term["type"]
    value = term.get("value")
    if kind == "ref":
        # Segments are path components, not references of their own: `lib.x` must not also
        # read as the bare var `lib` (which would resolve to every rule in that package).
        for child in (value or [])[1:]:
            if child.get("type") not in {"var", "string"}:
                yield from _iter_subterms(child)
    elif kind in {"call", "array", "set"}:
        for child in value or []:
            yield from _iter_subterms(child)
    elif kind == "object":
        for pair in value or []:
            for child in pair:
                yield from _iter_subterms(child)
    elif kind in {"arraycomprehension", "setcomprehension"} and value:
        yield from _iter_subterms(value["term"])
    elif kind == "objectcomprehension" and value:
        yield from _iter_subterms(value["key"])
        yield from _iter_subterms(value["value"])


def _expr_terms(expr: Expr) -> list[Term]:
    """Top-level terms of an expression in any of its syntactic forms."""
    terms = expr["terms"]
    if isinstance(terms, list):
        return terms
    if "symbols" in terms:
        return list(terms["symbols"])
    if "domain" in terms:  # every
        return [t for t in (terms.get("key"), terms.get("value"), terms["domain"]) if t]
    return [terms]


def _nested_bodies(expr: Expr) -> list[list[Expr]]:
    bodies: list[list[Expr]] = []
    terms = expr["terms"]
    if isinstance(terms, dict) and "domain" in terms:
        bodies.append(list(terms["body"]))
    for term in _expr_all_terms(expr):
        if term["type"] in {"arraycomprehension", "setcomprehension", "objectcomprehension"}:
            bodies.append(list(term["value"]["body"]))
    return bodies


def _expr_all_terms(expr: Expr) -> list[Term]:
    return [sub for top in _expr_terms(expr) for sub in _iter_subterms(top)]


def _walk(body: list[Expr], preceding: list[Expr]) -> Iterator[tuple[Expr, list[Expr]]]:
    """Yield (expr, exprs-that-precede-it) through nested every/comprehension bodies."""
    for i, expr in enumerate(body):
        before = [*preceding, *body[:i]]
        yield expr, before
        for nested in _nested_bodies(expr):
            yield from _walk(nested, before)


def _rule_bodies(rule: Rule) -> list[list[Expr]]:
    return [rule.body, *[list(e.get("body") or []) for e in rule.else_chain]]


def _rule_head_terms(rule: Rule) -> list[Term]:
    out: list[Term] = []
    for head in (rule.head, *[e["head"] for e in rule.else_chain]):
        for key in ("value", "key"):
            if head.get(key):
                out.extend(_iter_subterms(head[key]))
    return out


def _all_terms(rule: Rule) -> list[Term]:
    out = _rule_head_terms(rule)
    for body in _rule_bodies(rule):
        for expr, _ in _walk(body, []):
            out.extend(_expr_all_terms(expr))
    return out


# ---------------------------------------------------------------- resolution / call graph


class Resolver:
    def __init__(self, bundle: Bundle) -> None:
        self.rules = bundle.rules_by_path()
        self.module_of: dict[int, tuple[RulePath, dict[str, RulePath]]] = {}
        for module in bundle.modules:
            for rule in module.rules:
                self.module_of[id(rule)] = (module.package, module.imports)

    def absolute(self, term: Term, rule: Rule) -> list[str | None] | None:
        """Rule-path pattern a term refers to; None for a local var, builtin, or input read.

        A sibling rule in the same package is referenced as a bare `var` term, not a `ref`
        (`count(matched)`), so resolving vars is what makes same-package edges visible.
        """
        if term.get("type") == "var":
            segs: list[str | None] = [str(term["value"])]
        else:
            resolved = _ref_segments(term)
            if not resolved:
                return None
            segs = resolved
        if segs[0] in {"input", None}:
            return None
        package, imports = self.module_of[id(rule)]
        root = segs[0]
        if root == "data":
            return segs
        if root in imports:
            return [*imports[root], *segs[1:]]
        same_package = (*package, root)
        if any(p[: len(same_package)] == same_package for p in self.rules):
            return [*package, *segs]
        return None

    def matches(self, pattern: list[str | None]) -> list[RulePath]:
        out: list[RulePath] = []
        for path in self.rules:
            n = min(len(path), len(pattern))
            if all(pattern[i] is None or pattern[i] == path[i] for i in range(n)):
                out.append(path)
        return out

    def referenced_in_bodies(self, rule: Rule) -> set[RulePath]:
        """Rules used as *conditions* (body expressions), not merely as data in a head value."""
        found: set[RulePath] = set()
        for body in _rule_bodies(rule):
            for expr, _ in _walk(body, []):
                for term in _expr_all_terms(expr):
                    pattern = self.absolute(term, rule)
                    if pattern is not None:
                        found.update(self.matches(pattern))
        return found

    def referenced(self, rule: Rule) -> set[RulePath]:
        found: set[RulePath] = set()
        for term in _all_terms(rule):
            pattern = self.absolute(term, rule)
            if pattern is not None:
                found.update(self.matches(pattern))
        return found

    def reachable_from(self, entry: RulePath) -> list[RulePath]:
        seen: list[RulePath] = []
        frontier = [p for p in self.rules if p[: len(entry)] == entry]
        while frontier:
            path = frontier.pop()
            if path in seen:
                continue
            seen.append(path)
            for rule in self.rules[path]:
                frontier.extend(self.referenced(rule))
        return sorted(seen)

    def reads_input(self, paths: list[RulePath]) -> set[RulePath]:
        tainted: set[RulePath] = set()
        changed = True
        while changed:
            changed = False
            for path in paths:
                if path in tainted:
                    continue
                for rule in self.rules[path]:
                    direct = any(
                        (segs := _ref_segments(t)) is not None and segs[0] == "input"
                        for t in _all_terms(rule)
                    )
                    if direct or (self.referenced(rule) & tainted):
                        tainted.add(path)
                        changed = True
                        break
        return tainted


# ---------------------------------------------------------------- per-rule checks


def _is_permissive_value(term: Term | None) -> bool:
    if not term:
        return False
    if term["type"] == "boolean":
        return bool(term["value"])
    if term["type"] == "object":
        for key, value in term["value"]:
            if key.get("type") == "string" and key["value"] == "allow":
                return _is_permissive_value(value)
    return False


def _is_falsy_value(term: Term | None) -> bool:
    if not term:
        return True
    kind, value = term["type"], term.get("value")
    if kind == "boolean":
        return not value
    if kind == "null":
        return True
    if kind == "number":
        return value == 0
    if kind == "string":
        return value == ""
    if kind in {"array", "set", "object"}:
        return not value or (kind == "object" and not _is_permissive_value(term))
    return False


def _deny_without_reason(term: Term) -> bool:
    if term.get("type") != "object":
        return False
    allow_false = False
    empty_reasons = False
    for key, value in term["value"]:
        if key.get("type") != "string":
            continue
        if key["value"] == "allow" and value.get("type") == "boolean" and value["value"] is False:
            allow_false = True
        if (
            key["value"] == "deny_reasons"
            and value.get("type") in {"array", "set"}
            and not value["value"]
        ):
            empty_reasons = True
    return allow_false and empty_reasons


class RuleChecker:
    def __init__(
        self, resolver: Resolver, input_rules: set[RulePath], rule: Rule, *, deny_context: bool
    ) -> None:
        self.resolver = resolver
        self.input_rules = input_rules
        self.rule = rule
        self.deny_context = deny_context
        self.tainted_vars: set[str] = set()

    def _function_params(self) -> set[str]:
        """Function parameters are treated as input-derived: callers pass claims through them."""
        names: set[str] = set()
        for head in (self.rule.head, *[e["head"] for e in self.rule.else_chain]):
            for arg in head.get("args") or []:
                for sub in _iter_subterms(arg):
                    if sub["type"] == "var":
                        names.add(str(sub["value"]))
        return names

    def _reads_input(self, term: Term) -> bool:
        for sub in _iter_subterms(term):
            segs = _ref_segments(sub)
            if segs and segs[0] == "input":
                return True
            if sub["type"] == "var" and sub["value"] in self.tainted_vars:
                return True
            pattern = self.resolver.absolute(sub, self.rule)
            if pattern is not None and set(self.resolver.matches(pattern)) & self.input_rules:
                return True
        return False

    def _track_taint(self, expr: Expr) -> None:
        terms = expr["terms"]
        if isinstance(terms, dict) and "domain" in terms:
            if self._reads_input(terms["domain"]):
                for t in (terms.get("key"), terms.get("value")):
                    if t and t["type"] == "var":
                        self.tainted_vars.add(str(t["value"]))
            return
        if isinstance(terms, dict) and "symbols" in terms:
            for sym in terms["symbols"]:
                if sym["type"] == "call" and _builtin_name(sym["value"][0]) == "internal.member_2":
                    args = sym["value"][1:]
                    if self._reads_input(args[-1]):
                        for t in args[:-1]:
                            if t["type"] == "var":
                                self.tainted_vars.add(str(t["value"]))
            return
        if isinstance(terms, list) and len(terms) == 3:
            op = _builtin_name(terms[0])
            if op in {"assign", "eq"} and terms[1]["type"] == "var" and self._reads_input(terms[2]):
                self.tainted_vars.add(str(terms[1]["value"]))

    @staticmethod
    def _guarded_claim(expr: Expr) -> Term | None:
        """If `expr` is a presence+type guard, the guarded term; else None."""
        terms = expr["terms"]
        if not isinstance(terms, list) or expr.get("negated"):
            return None
        op = _builtin_name(terms[0])
        if op in TYPE_GUARDS and len(terms) == 2:
            guarded: Term = terms[1]
            return guarded
        if op == "internal.member_2" and len(terms) == 3 and terms[2]["type"] in {"set", "array"}:
            if all(t["type"] in {"string", "number", "boolean"} for t in terms[2]["value"]):
                member: Term = terms[1]
                return member
        if op in {"equal", "eq"} and len(terms) == 3:
            for lhs, rhs in ((terms[1], terms[2]), (terms[2], terms[1])):
                if lhs["type"] == "call" and _builtin_name(lhs["value"][0]) == "type_name":
                    if rhs["type"] == "string" and len(lhs["value"]) == 2:
                        typed: Term = lhs["value"][1]
                        return typed
        return None

    @staticmethod
    def _non_empty_guard(expr: Expr) -> Term | None:
        terms = expr["terms"]
        if not isinstance(terms, list) or len(terms) != 3 or expr.get("negated"):
            return None
        op = _builtin_name(terms[0])
        for count_side, bound in ((terms[1], terms[2]), (terms[2], terms[1])):
            if count_side["type"] != "call" or _builtin_name(count_side["value"][0]) != "count":
                continue
            if bound["type"] != "number":
                continue
            n = bound["value"]
            flipped = count_side is terms[2]
            effective = (
                {"gt": "lt", "gte": "lte", "lt": "gt", "lte": "gte"}.get(op or "", op)
                if flipped
                else op
            )
            if (
                (effective == "gt" and n >= 0)
                or (effective == "gte" and n >= 1)
                or (effective == "neq" and n == 0)
            ):
                counted: Term = count_side["value"][1]
                return counted
        return None

    def _claim_refs(self, expr: Expr) -> list[Term]:
        out: list[Term] = []
        guarded = self._guarded_claim(expr)
        guarded_key = _key(guarded) if guarded else None
        for term in _expr_all_terms(expr):
            segs = _ref_segments(term)
            if not segs or len(segs) < 3 or any(s is None for s in segs):
                continue
            if tuple(segs[:2]) == CLAIM_PREFIX and _key(term) != guarded_key:
                out.append(term)
        return out

    def _iteration_domains(self, expr: Expr) -> list[Term]:
        domains: list[Term] = []
        terms = expr["terms"]
        if isinstance(terms, dict) and "domain" in terms:
            domains.append(terms["domain"])
        for term in _expr_all_terms(expr):
            if term["type"] in {"arraycomprehension", "setcomprehension", "objectcomprehension"}:
                for inner, _ in _walk(list(term["value"]["body"]), []):
                    inner_terms = inner["terms"]
                    if isinstance(inner_terms, dict) and "symbols" in inner_terms:
                        for sym in inner_terms["symbols"]:
                            if (
                                sym["type"] == "call"
                                and _builtin_name(sym["value"][0]) == "internal.member_2"
                            ):
                                domains.append(sym["value"][-1])
                    for t in _expr_all_terms(inner):
                        segs = _ref_segments(t)
                        if segs and len(segs) > 1 and segs[-1] is None and segs[0] == "input":
                            domains.append({"type": "ref", "value": t["value"][:-1]})
        return domains

    def findings(self) -> Iterator[Finding]:
        rule = self.rule
        loc = rule.location
        if rule.is_default and not _is_falsy_value(rule.head.get("value")):
            yield Finding(
                Code.PERMISSIVE_DEFAULT, rule.dotted, loc, "default value can satisfy an allow path"
            )
        for else_rule in rule.else_chain:
            if _is_permissive_value(else_rule["head"].get("value")):
                yield Finding(
                    Code.PERMISSIVE_ELSE, rule.dotted, loc, "`else` yields a permissive value"
                )
        for head_term in _rule_head_terms(rule):
            if _deny_without_reason(head_term):
                yield Finding(
                    Code.DENY_WITHOUT_REASON,
                    rule.dotted,
                    loc,
                    "allow=false with empty deny_reasons (F3)",
                )
        if self.deny_context:
            return
        for body in _rule_bodies(rule):
            self.tainted_vars = self._function_params()
            for expr, before in _walk(body, []):
                at = (
                    Location(rule.file, expr["location"]["row"], expr["location"]["col"])
                    if expr.get("location")
                    else loc
                )
                self._track_taint(expr)
                if expr.get("with"):
                    yield Finding(
                        Code.WITH_OVERRIDE,
                        rule.dotted,
                        at,
                        "`with` rewrites input/data at evaluation time (fabricated claims)",
                    )
                if expr.get("negated") and any(self._reads_input(t) for t in _expr_terms(expr)):
                    yield Finding(
                        Code.NOT_OVER_INPUT,
                        rule.dotted,
                        at,
                        "`not` over an expression that reads input",
                    )
                for term in _expr_all_terms(expr):
                    if (
                        term["type"] == "call"
                        and _builtin_name(term["value"][0]) in MASKING_BUILTINS
                    ):
                        if any(self._reads_input(a) for a in term["value"][1:]):
                            yield Finding(
                                Code.MASKING_BUILTIN,
                                rule.dotted,
                                at,
                                f"{_builtin_name(term['value'][0])} masks an absent input value",
                            )
                guards = {_key(g) for g in (self._guarded_claim(e) for e in before) if g}
                for claim in self._claim_refs(expr):
                    if _key(claim) not in guards:
                        dotted = ".".join(s or "_" for s in _ref_segments(claim) or [])
                        yield Finding(
                            Code.UNGUARDED_CLAIM,
                            rule.dotted,
                            at,
                            f"{dotted} used without a prior presence+type guard",
                        )
                non_empty = {_key(g) for g in (self._non_empty_guard(e) for e in before) if g}
                for domain in self._iteration_domains(expr):
                    if self._reads_input(domain) and _key(domain) not in non_empty:
                        yield Finding(
                            Code.UNGUARDED_ITERATION,
                            rule.dotted,
                            at,
                            "iterates input with no prior count(...) > 0 guard (vacuous truth)",
                        )


# ---------------------------------------------------------------- entry point


def validate(bundle: Bundle, entry: RulePath = DEFAULT_ENTRY) -> Report:
    resolver = Resolver(bundle)
    entry_dotted = ".".join(entry)
    if entry not in resolver.rules:
        return Report(
            False,
            entry_dotted,
            (),
            (
                Finding(
                    Code.MISSING_ENTRY, entry_dotted, None, "decision entry point is not defined"
                ),
            ),
        )
    reachable = resolver.reachable_from(entry)
    input_rules = resolver.reads_input(reachable)
    # A deny-named rule is exempt only while it is never used as a condition by an allow-side
    # rule; naming a helper `deny_*` and calling it from `allow` buys no exemption.
    used_as_condition: set[RulePath] = set()
    for path in reachable:
        for rule in resolver.rules[path]:
            if not rule.name.startswith("deny"):
                used_as_condition |= resolver.referenced_in_bodies(rule)
    findings: list[Finding] = []
    for path in reachable:
        deny_context = path[-1].startswith("deny") and path not in used_as_condition
        for rule in resolver.rules[path]:
            checker = RuleChecker(resolver, input_rules, rule, deny_context=deny_context)
            findings.extend(checker.findings())
    unique = tuple(dict.fromkeys(findings))
    return Report(not unique, entry_dotted, tuple(".".join(p) for p in reachable), unique)
