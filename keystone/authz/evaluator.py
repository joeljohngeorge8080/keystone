"""PolicyEvaluator seam (Ch. 54) and the OPA sidecar HTTP implementation (Ch. 19/21).

The decision object is validated with a strict schema; any shape violation is a deny plus alert,
never a permissive default. OPA timeout is 150 ms with one retry inside a 400 ms budget, then 503.
"""

from __future__ import annotations

import hashlib
import time
from typing import Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from keystone.audit.canonical import canonicalize
from keystone.db.redis import DependencyUnavailable
from keystone.registry.models import NAME_PATTERN

DECISION_PATH = "/v1/data/keystone/authz/decision"
OPA_TIMEOUT_SECONDS = 0.150
OPA_BUDGET_SECONDS = 0.400
INPUT_SCHEMA_VERSION = 1


class Decision(BaseModel):
    """Ch. 19 decision object. Strict: extra keys, wrong types, empty deny reasons rejected."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    allow: bool
    grant: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9_-]{1,63}$")
    ttl_cap_seconds: int = Field(ge=0, le=3600)
    session_policy_ref: str | None = Field(default=None, pattern=NAME_PATTERN)
    rule_path: str | None = Field(default=None, min_length=1, max_length=256)
    deny_reasons: list[str] = Field(max_length=32)
    obligations: dict[str, JsonValue]
    loaded_bundle_digest: str = Field(min_length=1, max_length=128)


class DecisionMalformed(Exception):
    """Policy returned something outside the contract: treated as deny + alert (Ch. 19)."""

    http_status = 500
    code = "POLICY_DECISION_MALFORMED"


class PolicyInput(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    schema_version: int = Field(default=INPUT_SCHEMA_VERSION, alias="schema")
    identity: dict[str, JsonValue]
    request: dict[str, JsonValue]
    context: dict[str, JsonValue]

    def canonical(self) -> bytes:
        return canonicalize(self.model_dump(by_alias=True))

    def input_hash(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()


class PolicyEvaluator(Protocol):
    def evaluate(self, policy_input: PolicyInput) -> Decision: ...


def validate_decision(raw: object) -> Decision:
    if not isinstance(raw, dict):
        raise DecisionMalformed("decision is not an object")
    try:
        decision = Decision.model_validate(raw)
    except ValidationError as exc:
        raise DecisionMalformed(f"decision failed schema: {exc.error_count()} error(s)") from exc
    if not decision.allow and not decision.deny_reasons:
        raise DecisionMalformed("deny without deny_reasons (F3 explainability)")
    if decision.allow and (
        decision.grant is None
        or decision.session_policy_ref is None
        or decision.rule_path is None
        or decision.ttl_cap_seconds < 900
        or decision.deny_reasons
    ):
        raise DecisionMalformed("allow without a complete grant binding")
    return decision


class OpaHttpEvaluator:
    def __init__(self, base_url: str, *, client: httpx.Client | None = None) -> None:
        if not base_url.startswith("http://127.0.0.1") and not base_url.startswith(
            "http://localhost"
        ):
            raise ValueError("OPA is a localhost sidecar (Ch. 21); refusing a non-local address")
        self._url = base_url.rstrip("/") + DECISION_PATH
        self._client = client or httpx.Client(timeout=OPA_TIMEOUT_SECONDS)

    def evaluate(self, policy_input: PolicyInput) -> Decision:
        body = {"input": policy_input.model_dump(by_alias=True)}
        started = time.monotonic()
        attempts = 0
        last_error: Exception | None = None
        while attempts < 2 and (time.monotonic() - started) < OPA_BUDGET_SECONDS:
            attempts += 1
            try:
                response = self._client.post(self._url, json=body, timeout=OPA_TIMEOUT_SECONDS)
            except httpx.HTTPError as exc:
                last_error = exc
                continue
            if response.status_code != 200:
                raise DependencyUnavailable("opa", f"HTTP {response.status_code}")
            payload = response.json()
            if not isinstance(payload, dict) or "result" not in payload:
                # `result` absent means the decision rule is undefined: that is a deny, but a
                # malformed one — the entry point must always produce a decision (Ch. 19).
                raise DecisionMalformed("decision undefined")
            return validate_decision(payload["result"])
        raise DependencyUnavailable("opa", type(last_error).__name__ if last_error else "budget")
