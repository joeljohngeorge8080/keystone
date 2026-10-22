"""R2 hostile matrix: the reference policy denies every derived input, and the generator
catches policies that are structurally valid but too permissive."""

import io
import json
import shutil
from pathlib import Path

import pytest

from keystone.authz.policy_verify.hostile import cases_for, main, referenced_claims

REPO = Path(__file__).resolve().parents[2]
POLICIES = REPO / "policies"
SEEDS = REPO / "tests" / "policy" / "hostile_seeds.json"
GRANT = Path("keystone") / "grants" / "deploy_prod.rego"

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not on PATH")


def _run(root: Path, seeds: Path = SEEDS) -> tuple[int, str]:
    out = io.StringIO()
    code = main([str(root), "--seeds", str(seeds)], out)
    return code, out.getvalue()


def _variant(tmp_path: Path, drop: str) -> Path:
    root = tmp_path / "policies"
    shutil.copytree(POLICIES, root)
    grant = root / GRANT
    source = grant.read_text()
    assert drop in source
    grant.write_text(source.replace(drop, ""))
    return root


def test_reference_policy_denies_the_whole_matrix() -> None:
    code, out = _run(POLICIES)
    assert code == 0, out
    assert "0 allowed" in out


def test_every_referenced_claim_gets_absent_and_wrong_type_cases() -> None:
    claims = referenced_claims(POLICIES)
    assert {"repository", "ref", "event_name", "repository_id", "repository_owner"} <= claims
    seed = json.loads(SEEDS.read_text())[0]
    names = {c.name for c in cases_for(seed["name"], seed["input"], claims)}
    for claim in claims & seed["input"]["identity"].keys():
        assert f"{claim}: absent" in names
        assert {f"{claim}: {t}" for t in ("number", "bool", "list", "object", "null")} <= names


def test_a_grant_that_forgets_the_event_check_is_caught(tmp_path: Path) -> None:
    root = _variant(tmp_path, '\tinput.identity.event_name in {"push", "workflow_dispatch"}\n')
    code, out = _run(root)
    assert code == 1
    assert "HOSTILE INPUT ALLOWED: deploy-prod: push to main: fork: event_name=pull_request" in out


def test_a_grant_that_forgets_the_repository_id_is_caught(tmp_path: Path) -> None:
    root = _variant(tmp_path, '\tinput.identity.repository_id == "42"\n')
    code, out = _run(root)
    assert code == 1
    assert "near-miss repository_id" in out


def test_a_seed_the_policy_does_not_allow_is_refused(tmp_path: Path) -> None:
    seeds = json.loads(SEEDS.read_text())
    seeds[0]["input"]["identity"]["ref"] = "refs/heads/dev"
    path = tmp_path / "seeds.json"
    path.write_text(json.dumps(seeds))
    code, out = _run(POLICIES, path)
    assert code == 2 and "SEED NOT ALLOWED" in out


def test_a_grant_without_a_seed_fails_the_run(tmp_path: Path) -> None:
    root = tmp_path / "policies"
    shutil.copytree(POLICIES, root)
    extra = root / "keystone" / "grants" / "deploy_staging.rego"
    extra.write_text(
        (root / GRANT)
        .read_text()
        .replace("keystone.grants.deploy_prod", "keystone.grants.deploy_staging")
        .replace('"deploy-prod"', '"deploy-staging"')
    )
    code, out = _run(root)
    assert code == 2 and "GRANTS WITHOUT A SEED: deploy-staging" in out
