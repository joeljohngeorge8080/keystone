"""Decision-object contract (Ch. 19, F3): shape violations are rejected, never defaulted."""

from typing import Any

import pytest

from keystone.authz.evaluator import DecisionMalformed, PolicyInput, validate_decision

ALLOW: dict[str, Any] = {
    "allow": True,
    "grant": "deploy_prod",
    "ttl_cap_seconds": 900,
    "session_policy_ref": "s3-deploy-narrow",
    "rule_path": "keystone.grants.deploy_prod",
    "deny_reasons": [],
    "obligations": {"require_environment": "production"},
    "loaded_bundle_digest": "sha256:" + "ab" * 32,
}
DENY: dict[str, Any] = {
    "allow": False,
    "grant": None,
    "ttl_cap_seconds": 0,
    "session_policy_ref": None,
    "rule_path": None,
    "deny_reasons": ["NO_GRANT_MATCHED"],
    "obligations": {},
    "loaded_bundle_digest": "sha256:" + "ab" * 32,
}


def test_well_formed_allow_and_deny() -> None:
    assert validate_decision(ALLOW).allow is True
    assert validate_decision(DENY).deny_reasons == ["NO_GRANT_MATCHED"]


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "allow",
        [],
        {},
        {**DENY, "deny_reasons": []},  # F3: deny must explain itself
        {**ALLOW, "allow": "true"},  # strict types
        {**ALLOW, "ttl_cap_seconds": 899},  # allow below the floor
        {**ALLOW, "ttl_cap_seconds": 3601},
        {**ALLOW, "grant": None},
        {**ALLOW, "session_policy_ref": None},
        {**ALLOW, "rule_path": None},
        {**ALLOW, "deny_reasons": ["X"]},  # allow with reasons is contradictory
        {**ALLOW, "extra": 1},
        {**ALLOW, "loaded_bundle_digest": ""},
        {k: v for k, v in ALLOW.items() if k != "obligations"},
        {**ALLOW, "grant": "Bad Grant"},
        {**ALLOW, "deny_reasons": ["r"] * 33},
    ],
)
def test_malformed_decisions_are_rejected(raw: object) -> None:
    with pytest.raises(DecisionMalformed):
        validate_decision(raw)


def test_policy_input_hash_is_canonical_and_stable() -> None:
    a = PolicyInput(
        schema=1,
        identity={"sub": "s", "repository": "acme/app"},
        request={"grant": "deploy-prod", "requested_ttl_seconds": None},
        context={"keystone_version": "0.1.0", "policy_version": "sha256:x"},
    )
    b = PolicyInput(
        schema=1,
        identity={"repository": "acme/app", "sub": "s"},
        request={"requested_ttl_seconds": None, "grant": "deploy-prod"},
        context={"policy_version": "sha256:x", "keystone_version": "0.1.0"},
    )
    assert a.input_hash() == b.input_hash() and len(a.input_hash()) == 64
    assert a.canonical().startswith(b'{"context":')
