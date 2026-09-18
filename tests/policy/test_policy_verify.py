"""keystone-policy-verify against the fixture bundles: one negative per R2 rejection class."""

import io
import json
import shutil
from pathlib import Path

import pytest

from keystone.authz.policy_verify.loader import load_bundle
from keystone.authz.policy_verify.main import main
from keystone.authz.policy_verify.validator import Code, validate

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "policy_verify"

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not on PATH")


def _codes(bundle_dir: Path) -> tuple[set[Code], list[str]]:
    report = validate(load_bundle(bundle_dir))
    return {f.code for f in report.findings}, [f.rule for f in report.findings]


def test_reference_policy_passes() -> None:
    report = validate(load_bundle(REPO / "policies"))
    assert report.ok, report.findings
    assert "data.keystone.grants.deploy_prod.allow" in report.reachable
    assert "data.keystone.lib.identity_present" in report.reachable


def test_guarded_every_and_deny_context_negation_pass() -> None:
    report = validate(load_bundle(FIXTURES / "p2_guarded_every_and_deny_not"))
    assert report.ok, report.findings


@pytest.mark.parametrize(
    ("fixture", "code", "rule"),
    [
        ("n1_not_over_input", Code.NOT_OVER_INPUT, "data.keystone.grants.deploy_prod.allow"),
        ("n2_not_transitive", Code.NOT_OVER_INPUT, "data.keystone.lib.not_a_fork"),
        ("n3_default_true", Code.PERMISSIVE_DEFAULT, "data.keystone.grants.deploy_prod.allow"),
        ("n4_default_decision_allow", Code.PERMISSIVE_DEFAULT, "data.keystone.authz.decision"),
        ("n5_object_get_default", Code.MASKING_BUILTIN, "data.keystone.grants.deploy_prod.allow"),
        ("n6_every_unguarded", Code.UNGUARDED_ITERATION, "data.keystone.grants.deploy_prod.allow"),
        (
            "n7_comprehension_unguarded",
            Code.UNGUARDED_ITERATION,
            "data.keystone.grants.deploy_prod.allow",
        ),
        ("n8_unguarded_claim", Code.UNGUARDED_CLAIM, "data.keystone.grants.deploy_prod.allow"),
        ("n9_else_true", Code.PERMISSIVE_ELSE, "data.keystone.grants.deploy_prod.allow"),
        ("n10_missing_entry", Code.MISSING_ENTRY, "data.keystone.authz.decision"),
        ("n11_deny_without_reason", Code.DENY_WITHOUT_REASON, "data.keystone.authz.decision"),
        ("n12_with_input_override", Code.WITH_OVERRIDE, "data.keystone.grants.deploy_prod.allow"),
        ("n13_negation_in_function", Code.NOT_OVER_INPUT, "data.keystone.lib.not_true"),
        ("n14_deny_named_helper", Code.NOT_OVER_INPUT, "data.keystone.lib.deny_if_fork"),
    ],
)
def test_each_rejection_class_is_caught_at_the_right_rule(
    fixture: str, code: Code, rule: str
) -> None:
    codes, rules = _codes(FIXTURES / fixture)
    assert code in codes, (codes, rules)
    assert rule in rules


def test_negative_fixtures_never_pass() -> None:
    for fixture in sorted(FIXTURES.glob("n*")):
        assert not validate(load_bundle(fixture)).ok, fixture.name


def test_cli_exit_codes_and_precise_locations(tmp_path: Path) -> None:
    ok = io.StringIO()
    assert main([str(REPO / "policies")], out=ok) == 0
    assert ok.getvalue().startswith("OK:")

    rejected = io.StringIO()
    assert main([str(FIXTURES / "n1_not_over_input")], out=rejected) == 1
    text = rejected.getvalue()
    assert (
        "NOT_OVER_INPUT data.keystone.grants.deploy_prod.allow (keystone/grants/deploy_prod.rego:"
        in text
    )

    as_json = io.StringIO()
    assert main([str(FIXTURES / "n8_unguarded_claim"), "--json"], out=as_json) == 1
    payload = json.loads(as_json.getvalue())
    assert payload["ok"] is False
    assert payload["findings"][0]["code"] == "UNGUARDED_CLAIM"

    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "x.rego").write_text("package keystone.authz\n\ndecision := {\n")
    assert main([str(broken)], out=io.StringIO()) == 2
    assert main([str(tmp_path / "missing")], out=io.StringIO()) == 2
