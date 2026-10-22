"""keystone-auth GitHub Action (Ch. 46): masking first, fresh token per retry, bounded retry."""

from __future__ import annotations

import importlib.util
import io
import json
import urllib.error
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ACTION = Path(__file__).resolve().parents[2] / "action" / "keystone_auth.py"
OIDC_URL = "https://pipelines.example/idtoken?api-version=2.0"
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SESSION = "FwoGZXIvYXdzEJr//////////wEaDEXAMPLESESSIONTOKEN=="


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("keystone_auth", ACTION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ka = _load()


class Reply:
    def __init__(self, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self._raw = json.dumps(body).encode()
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> Reply:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class Broker:
    """Fake OIDC issuer + Keystone public plane; scripted broker statuses, one per attempt."""

    def __init__(self, *script: tuple[int, Any, dict[str, str]]) -> None:
        self.script = list(script)
        self.tokens_issued: list[str] = []
        self.tokens_presented: list[str] = []
        self.audiences: list[str | None] = []

    def __call__(self, request: Any, timeout: float) -> Reply:
        url = request.full_url
        if url.startswith(OIDC_URL):
            assert request.headers["Authorization"] == "bearer runtime-token"
            self.audiences.append(url.partition("audience=")[2] or None)
            token = f"jwt-{len(self.tokens_issued)}"
            self.tokens_issued.append(token)
            return Reply(200, {"value": token})
        assert url == "https://keystone.example/v1/credentials"
        self.tokens_presented.append(json.loads(request.data)["token"])
        status, body, headers = self.script.pop(0)
        if status >= 400:
            raise urllib.error.HTTPError(
                url,
                status,
                "x",
                headers,  # type: ignore[arg-type]
                io.BytesIO(json.dumps(body).encode()),
            )
        return Reply(status, body, headers)


ISSUED: tuple[int, Any, dict[str, str]] = (
    201,
    {
        "decision_id": "01a16400-0000-7000-8000-000000000001",
        "grant": "deploy-prod",
        "credentials": {
            "access_key_id": "ASIAEXAMPLE0000000AB",
            "secret_access_key": SECRET,
            "session_token": SESSION,
            "expiration": "2026-10-22T18:00:00+00:00",
        },
        "granted_ttl_seconds": 900,
        "ttl_clamped": False,
        "region_hint": "eu-west-1",
        "audit_seq": 2,
    },
    {},
)


def _unavailable(retry_after: str = "5") -> tuple[int, Any, dict[str, str]]:
    error = {"code": "KEYSTONE_DEPENDENCY_UNAVAILABLE", "message": "m", "retryable": True}
    return 503, {"error": error}, {"Retry-After": retry_after}


@pytest.fixture
def runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name, value in {
        "INPUT_KEYSTONE_URL": "https://keystone.example",
        "INPUT_GRANT": "deploy-prod",
        "INPUT_TTL_SECONDS": "900",
        "INPUT_RETRY": "3",
        "INPUT_AUDIENCE": "",
        "ACTIONS_ID_TOKEN_REQUEST_URL": OIDC_URL,
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runtime-token",
        "GITHUB_ENV": str(tmp_path / "env"),
        "GITHUB_OUTPUT": str(tmp_path / "output"),
    }.items():
        monkeypatch.setenv(name, value)
    return tmp_path


def _exports(path: Path) -> dict[str, str]:
    lines = path.read_text().splitlines()
    values: dict[str, str] = {}
    i = 0
    while i < len(lines):
        name, _, delimiter = lines[i].partition("<<")
        assert lines[i + 2] == delimiter and delimiter.startswith("ghadelim_")
        values[name] = lines[i + 1]
        i += 3
    return values


def test_issue_masks_before_anything_else_then_exports(runner: Path) -> None:
    out = io.StringIO()
    broker = Broker(ISSUED)
    assert ka.run(out=out, opener=broker, sleep=lambda s: None) == 0
    lines = out.getvalue().splitlines()
    assert lines[:3] == [
        "::add-mask::ASIAEXAMPLE0000000AB",
        f"::add-mask::{SECRET}",
        f"::add-mask::{SESSION}",
    ]
    assert all(SECRET not in line and SESSION not in line for line in lines[3:])
    exported = _exports(runner / "env")
    assert exported["AWS_SECRET_ACCESS_KEY"] == SECRET
    assert exported["AWS_SESSION_TOKEN"] == SESSION
    assert exported["AWS_REGION"] == "eu-west-1"
    assert exported["KEYSTONE_DECISION_ID"] == ISSUED[1]["decision_id"]
    assert _exports(runner / "output") == {"decision_id": ISSUED[1]["decision_id"]}


def test_503_retries_with_a_fresh_oidc_token_each_time(runner: Path) -> None:
    slept: list[float] = []
    broker = Broker(_unavailable("1"), _unavailable("1"), ISSUED)
    assert ka.run(out=io.StringIO(), opener=broker, sleep=slept.append) == 0
    assert slept == [2.0, 4.0]  # Ch. 28: 2/4/8 s
    assert broker.tokens_presented == ["jwt-0", "jwt-1", "jwt-2"]  # never the same JTI twice


def test_retry_after_is_honoured_up_to_a_cap(runner: Path) -> None:
    slept: list[float] = []
    broker = Broker(_unavailable("20"), _unavailable("3600"), ISSUED)
    assert ka.run(out=io.StringIO(), opener=broker, sleep=slept.append) == 0
    assert slept == [20.0, 30.0]


def test_gives_up_after_the_bounded_retries(runner: Path) -> None:
    slept: list[float] = []
    broker = Broker(*[_unavailable("1")] * 4)
    with pytest.raises(ka.ActionError, match="giving up after 4 attempts"):
        ka.run(out=io.StringIO(), opener=broker, sleep=slept.append)
    assert slept == [2.0, 4.0, 8.0]


def test_denial_prints_the_explanation_and_never_retries(runner: Path) -> None:
    denied: tuple[int, Any, dict[str, str]] = (
        403,
        {
            "decision_id": "d-1",
            "error": {
                "code": "POLICY_DENIED",
                "reasons": ["NO_GRANT_MATCHED"],
                "rule_path": None,
                "policy_digest": "sha256:ab",
            },
        },
        {},
    )
    broker = Broker(denied, ISSUED)
    with pytest.raises(ka.ActionError, match=r"NO_GRANT_MATCHED.*sha256:ab"):
        ka.run(out=io.StringIO(), opener=broker, sleep=lambda s: None)
    assert len(broker.tokens_presented) == 1
    assert not (runner / "env").exists()


@pytest.mark.parametrize(
    ("status", "code"), [(409, "TOKEN_REPLAYED"), (401, "TOKEN_INVALID"), (500, "X")]
)
def test_other_errors_are_terminal(runner: Path, status: int, code: str) -> None:
    broker = Broker((status, {"error": {"code": code, "message": "m"}}, {}), ISSUED)
    with pytest.raises(ka.ActionError, match=code):
        ka.run(out=io.StringIO(), opener=broker, sleep=lambda s: None)
    assert len(broker.tokens_presented) == 1


def test_a_hostile_credential_value_is_masked_but_never_exported(runner: Path) -> None:
    status, body, headers = ISSUED
    hostile = json.loads(json.dumps(body))
    hostile["credentials"]["session_token"] = "tok\nAWS_ROLE_ARN=evil"
    out = io.StringIO()
    with pytest.raises(ka.ActionError, match="malformed AWS_SESSION_TOKEN"):
        ka.run(out=out, opener=Broker((status, hostile, headers)), sleep=lambda s: None)
    assert out.getvalue().startswith("::add-mask::")
    assert not (runner / "env").exists()


def test_audience_is_requested_when_configured(
    runner: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INPUT_AUDIENCE", "https://github.com/acme")
    broker = Broker(ISSUED)
    ka.run(out=io.StringIO(), opener=broker, sleep=lambda s: None)
    assert broker.audiences == ["https%3A%2F%2Fgithub.com%2Facme"]


@pytest.mark.parametrize(
    ("name", "value", "match"),
    [
        ("INPUT_KEYSTONE_URL", "http://keystone.example", "https://"),
        ("INPUT_GRANT", "Deploy Prod", "grant must match"),
        ("INPUT_RETRY", "50", "between 0 and 9"),
        ("ACTIONS_ID_TOKEN_REQUEST_URL", "", "id-token: write"),
    ],
)
def test_bad_configuration_fails_before_any_request(
    runner: Path, monkeypatch: pytest.MonkeyPatch, name: str, value: str, match: str
) -> None:
    monkeypatch.setenv(name, value)
    broker = Broker(ISSUED)
    with pytest.raises(ka.ActionError, match=match):
        ka.run(out=io.StringIO(), opener=broker, sleep=lambda s: None)
    assert broker.tokens_presented == []
