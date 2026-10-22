"""Public-plane HTTP layer with a fake pipeline: transport validation, envelope, error mapping."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from keystone.api.app import MAX_BODY_BYTES, create_app
from keystone.api.credentials import (
    CredentialRequest,
    CredentialResponse,
    Credentials,
    Issued,
)
from keystone.api.ratelimit import RateLimited
from keystone.authz.service import Denied, NoActivePin, PolicyPinDivergence
from keystone.broker.connectors.base import (
    AccessDeniedError,
    IndeterminateError,
    TemplateError,
    UnavailableError,
)
from keystone.broker.service import PolicyRegistryDivergence, TtlDenied
from keystone.db.redis import DependencyUnavailable
from keystone.identity.jwks import JwksUnavailable
from keystone.identity.oidc import TokenRejected
from keystone.registry.repo import RegistryCode, RegistryError

TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
DIGEST = "sha256:" + "ab" * 32


class FakePipeline:
    def __init__(self, outcome: Issued | Denied | Exception | None = None) -> None:
        self.outcome = outcome
        self.requests: list[CredentialRequest] = []
        self.delivered: list[uuid.UUID] = []

    def handle(
        self, request: CredentialRequest, *, source_ip: str, request_id: str
    ) -> Issued | Denied:
        self.requests.append(request)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        if self.outcome is None:
            return _issued(request_id)
        return self.outcome

    def mark_delivered(self, issuance_id: uuid.UUID) -> None:
        self.delivered.append(issuance_id)


def _issued(request_id: str) -> Issued:
    return Issued(
        response=CredentialResponse(
            request_id=request_id,
            decision_id=uuid.UUID(int=1),
            grant="deploy-prod",
            credentials=Credentials(
                access_key_id="ASIAFAKE0123456789AB",
                secret_access_key="secret-value",
                session_token="session-value",
                expiration="2026-10-22T10:00:00+00:00",
            ),
            granted_ttl_seconds=900,
            ttl_clamped=False,
            region_hint="eu-west-1",
            audit_seq=2,
        ),
        issuance_id=uuid.UUID(int=7),
    )


def _client(pipeline: FakePipeline) -> TestClient:
    return TestClient(create_app(pipeline), raise_server_exceptions=False)


def _post(client: TestClient, body: Any, **kwargs: Any) -> Any:
    content = body if isinstance(body, bytes) else json.dumps(body).encode()
    headers = {"Content-Type": "application/json", **kwargs.pop("headers", {})}
    return client.post("/v1/credentials", content=content, headers=headers, **kwargs)


GOOD = {"token": TOKEN, "grant": "deploy-prod", "ttl_seconds": 900}


def _assert_common_headers(response: Any) -> None:
    assert response.headers["cache-control"] == "no-store"
    assert uuid.UUID(response.headers["x-request-id"])


def test_healthz_is_liveness_only() -> None:
    response = _client(FakePipeline()).get("/healthz")
    assert response.status_code == 200 and response.json() == {"status": "ok"}
    _assert_common_headers(response)


def test_issue_returns_201_then_marks_delivered() -> None:
    pipeline = FakePipeline()
    response = _post(_client(pipeline), GOOD)
    assert response.status_code == 201
    _assert_common_headers(response)
    body = response.json()
    assert body["request_id"] == response.headers["x-request-id"]
    assert body["credentials"]["secret_access_key"] == "secret-value"
    assert pipeline.requests[0].grant == "deploy-prod"
    assert pipeline.delivered == [uuid.UUID(int=7)]


def test_request_model_never_reprs_the_token() -> None:
    request = CredentialRequest.model_validate(GOOD)
    assert TOKEN not in repr(request) and TOKEN not in str(request)


@pytest.mark.parametrize(
    ("body", "headers", "status", "code"),
    [
        (GOOD, {"Content-Type": "text/plain"}, 415, "VALIDATION_CONTENT_TYPE"),
        (
            GOOD,
            {"Content-Type": "application/json; charset=latin-1"},
            415,
            "VALIDATION_CONTENT_TYPE",
        ),
        (b"\xff\xfe{}", {}, 400, "VALIDATION_ENCODING"),
        (b'{"token": "a", "token": "b"}', {}, 400, "VALIDATION_MALFORMED_JSON"),
        (
            b'{"token": "x.y.z", "grant": "g1", "ttl_seconds": NaN}',
            {},
            400,
            "VALIDATION_MALFORMED_JSON",
        ),
        (b"[1, 2]", {}, 400, "VALIDATION_FAILED"),
        ({**GOOD, "extra": 1}, {}, 400, "VALIDATION_FAILED"),
        ({**GOOD, "grant": "Deploy_Prod"}, {}, 400, "VALIDATION_FAILED"),
        ({**GOOD, "ttl_seconds": True}, {}, 400, "VALIDATION_FAILED"),
        ({**GOOD, "ttl_seconds": "900"}, {}, 400, "VALIDATION_FAILED"),
        ({**GOOD, "ttl_seconds": 86401}, {}, 400, "VALIDATION_FAILED"),
        ({**GOOD, "token": "not-a-jwt"}, {}, 400, "VALIDATION_FAILED"),
    ],
)
def test_transport_and_schema_rejections(
    body: Any, headers: dict[str, str], status: int, code: str
) -> None:
    pipeline = FakePipeline()
    response = _post(_client(pipeline), body, headers=headers)
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code
    _assert_common_headers(response)
    assert pipeline.requests == []  # nothing reached verification


def test_validation_errors_never_echo_hostile_input() -> None:
    hostile = "<script>alert(1)</script>"
    response = _post(_client(FakePipeline()), {**GOOD, "grant": hostile})
    assert response.status_code == 400
    assert hostile not in response.text
    assert response.json()["error"]["details"]["problems"] == [
        {"field": "grant", "error": "string_pattern_mismatch"}
    ]


def test_body_cap_applies_with_and_without_content_length() -> None:
    big = json.dumps({**GOOD, "pad": "x" * MAX_BODY_BYTES}).encode()
    client = _client(FakePipeline())
    assert _post(client, big).status_code == 413

    def chunks() -> Any:
        yield big[: len(big) // 2]
        yield big[len(big) // 2 :]

    response = client.post(
        "/v1/credentials", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "VALIDATION_BODY_TOO_LARGE"


@pytest.mark.parametrize(
    ("exc", "status", "code", "retryable"),
    [
        (TokenRejected("TOKEN_SIGNATURE_INVALID"), 401, "TOKEN_INVALID", False),
        (TokenRejected("TOKEN_EXPIRED"), 401, "TOKEN_INVALID", False),
        (TokenRejected("TOKEN_REPLAYED", http_status=409), 409, "TOKEN_REPLAYED", False),
        (
            DependencyUnavailable("redis", "ConnectionError"),
            503,
            "KEYSTONE_DEPENDENCY_UNAVAILABLE",
            True,
        ),
        (JwksUnavailable("origin down"), 503, "KEYSTONE_DEPENDENCY_UNAVAILABLE", True),
        (NoActivePin("none"), 503, "POLICY_PIN_MISSING", True),
        (PolicyPinDivergence("drift"), 503, "POLICY_PIN_DIVERGENCE", True),
        (
            RegistryError(RegistryCode.ROLE_DISABLED, "off"),
            500,
            "POLICY_REGISTRY_DIVERGENCE",
            False,
        ),
        (
            PolicyRegistryDivergence("POLICY_REGISTRY_DIVERGENCE", "cap"),
            500,
            "POLICY_REGISTRY_DIVERGENCE",
            False,
        ),
        (TtlDenied("requested ttl 3600s exceeds allowed 900s"), 403, "TTL_EXCEEDS_ALLOWED", False),
        (AccessDeniedError("trust drift"), 502, "STS_ACCESS_DENIED", False),
        (TemplateError("bad doc"), 500, "STS_POLICY_REJECTED", False),
        (UnavailableError("throttled"), 503, "STS_UNAVAILABLE", True),
        (IndeterminateError("timeout"), 503, "STS_INDETERMINATE", False),
    ],
)
def test_error_mapping(exc: Exception, status: int, code: str, retryable: bool) -> None:
    response = _post(_client(FakePipeline(exc)), GOOD)
    assert response.status_code == status
    error = response.json()["error"]
    assert error["code"] == code and error["retryable"] is retryable
    assert error["request_id"] == response.headers["x-request-id"]
    _assert_common_headers(response)


def test_pre_auth_failures_are_indistinguishable() -> None:
    bodies = {
        json.dumps(
            _post(_client(FakePipeline(TokenRejected(code))), GOOD).json()["error"]
            | {"request_id": None}
        )
        for code in (
            "TOKEN_MALFORMED",
            "TOKEN_SIGNATURE_INVALID",
            "TOKEN_KID_UNKNOWN",
            "TOKEN_EXPIRED",
            "TOKEN_AUDIENCE_REJECTED",
            "TOKEN_CLAIMS_INCOMPLETE",
        )
    }
    assert len(bodies) == 1


def test_dependency_and_sts_5xx_do_not_leak_internals() -> None:
    for exc in (
        DependencyUnavailable("redis", "ConnectionError at 10.0.0.5:6379"),
        AccessDeniedError("arn:aws:iam::123456789012:role/secret-role"),
    ):
        text = _post(_client(FakePipeline(exc)), GOOD).text
        assert "redis" not in text and "10.0.0.5" not in text and "arn:aws" not in text


def test_rate_limited_sets_retry_after() -> None:
    response = _post(
        _client(FakePipeline(RateLimited("RATE_LIMITED_IDENTITY", "identity", 17))), GOOD
    )
    assert response.status_code == 429 and response.headers["retry-after"] == "17"
    assert response.json()["error"]["details"] == {"scope": "identity"}


def test_unexpected_failure_is_a_generic_500() -> None:
    response = _post(_client(FakePipeline(RuntimeError("db password is hunter2"))), GOOD)
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "KEYSTONE_INTERNAL_ERROR"
    assert "hunter2" not in response.text
    _assert_common_headers(response)


def test_denial_body_explains_the_decision() -> None:
    denied = Denied(
        decision_id=uuid.UUID(int=3),
        audit_seq=1,
        reasons=("NO_GRANT_MATCHED",),
        rule_path=None,
        policy_digest=DIGEST,
    )
    pipeline = FakePipeline(denied)
    response = _post(_client(pipeline), GOOD)
    assert response.status_code == 403
    body = response.json()
    assert body["decision_id"] == str(uuid.UUID(int=3))
    assert body["error"]["code"] == "POLICY_DENIED"
    assert body["error"]["reasons"] == ["NO_GRANT_MATCHED"]
    assert body["error"]["policy_digest"] == DIGEST
    assert pipeline.delivered == []


def test_unknown_route_uses_the_envelope() -> None:
    client = _client(FakePipeline())
    response = client.get("/v1/nope")
    assert response.status_code == 404 and response.json()["error"]["code"] == "NOT_FOUND"
    _assert_common_headers(response)
    assert client.get("/v1/credentials").status_code == 405
