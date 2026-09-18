"""AwsStsConnector: moto for the golden path, botocore Stubber/fakes for error shaping (Ch. 58/59)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
import pytest
from botocore.exceptions import (
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)
from botocore.stub import Stubber
from moto import mock_aws

from keystone.broker.connectors.aws_sts import AwsStsConnector
from keystone.broker.connectors.base import (
    AccessDeniedError,
    IndeterminateError,
    MintRequest,
    ProtocolError,
    TemplateError,
    UnavailableError,
)

ARN = "arn:aws:iam::123456789012:role/keystone-deploy-prod"
REQUEST = MintRequest(
    role_arn=ARN,
    session_name="ks-42-7-3",
    duration_seconds=1800,
    session_policy={
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    },
    tags={
        "keystone:decision_id": "d1",
        "keystone:repository": "acme/app",
        "keystone:actor": "octocat",
    },
)


@pytest.fixture
def fake_aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@mock_aws
def test_golden_path_against_moto(fake_aws_env: None) -> None:
    connector = AwsStsConnector(region="us-east-1")
    credential = connector.mint(REQUEST)
    assert credential.access_key_id.startswith("ASIA")
    assert credential.secret_access_key and credential.session_token
    remaining = credential.expiration - datetime.now(UTC)
    assert timedelta(seconds=1700) < remaining <= timedelta(seconds=1800)
    assert "ASIA" in repr(credential) and credential.secret_access_key not in repr(credential)
    assert connector._client.meta.config.retries == {"total_max_attempts": 1, "mode": "standard"}
    assert connector.describe_capabilities().max_duration_seconds == 3600


def _stubbed(fake_aws_env: None) -> tuple[Any, Stubber, AwsStsConnector]:
    client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.activate()
    return client, stubber, AwsStsConnector(region="us-east-1", client=client)


def _ok_response(duration: int = 1800) -> dict[str, Any]:
    return {
        "Credentials": {
            "AccessKeyId": "ASIAOK000000000000",
            "SecretAccessKey": "s",
            "SessionToken": "t",
            "Expiration": datetime.now(UTC) + timedelta(seconds=duration),
        },
        "AssumedRoleUser": {"AssumedRoleId": "AROA:ks", "Arn": ARN},
    }


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("AccessDenied", AccessDeniedError),
        ("MalformedPolicyDocument", TemplateError),
        ("InvalidClientTokenId", UnavailableError),
        ("ExpiredToken", UnavailableError),
        ("RegionDisabledException", UnavailableError),
        ("SomethingNew", UnavailableError),
    ],
)
def test_client_errors_map_to_the_spec_classes(
    fake_aws_env: None, code: str, expected: type[Exception]
) -> None:
    _, stubber, connector = _stubbed(fake_aws_env)
    stubber.add_client_error("assume_role", service_error_code=code, http_status_code=400)
    with pytest.raises(expected):
        connector.mint(REQUEST)
    stubber.assert_no_pending_responses()


def test_throttling_is_retried_exactly_once(fake_aws_env: None) -> None:
    _, stubber, connector = _stubbed(fake_aws_env)
    stubber.add_client_error("assume_role", service_error_code="Throttling", http_status_code=429)
    stubber.add_response("assume_role", _ok_response())
    assert connector.mint(REQUEST).access_key_prefix == "ASIAOK00"
    stubber.assert_no_pending_responses()

    stubber.add_client_error("assume_role", service_error_code="Throttling", http_status_code=429)
    stubber.add_client_error("assume_role", service_error_code="Throttling", http_status_code=429)
    with pytest.raises(UnavailableError, match="throttled twice"):
        connector.mint(REQUEST)
    stubber.assert_no_pending_responses()


def test_request_shape_sent_to_sts(fake_aws_env: None) -> None:
    _, stubber, connector = _stubbed(fake_aws_env)
    stubber.add_response(
        "assume_role",
        _ok_response(),
        expected_params={
            "RoleArn": ARN,
            "RoleSessionName": "ks-42-7-3",
            "DurationSeconds": 1800,
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}',
            "Tags": [
                {"Key": "keystone:actor", "Value": "octocat"},
                {"Key": "keystone:decision_id", "Value": "d1"},
                {"Key": "keystone:repository", "Value": "acme/app"},
            ],
        },
    )
    connector.mint(REQUEST)
    stubber.assert_no_pending_responses()


class _TransportFailingClient:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.calls = 0

    def assume_role(self, **_: Any) -> dict[str, Any]:
        self.calls += 1
        raise self.exc


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (ReadTimeoutError(endpoint_url="https://sts"), IndeterminateError),
        (ConnectionClosedError(endpoint_url="https://sts"), IndeterminateError),
        (ConnectTimeoutError(endpoint_url="https://sts"), UnavailableError),
        (EndpointConnectionError(endpoint_url="https://sts"), UnavailableError),
    ],
)
def test_transport_failures_never_blind_retry(exc: Exception, expected: type[Exception]) -> None:
    client = _TransportFailingClient(exc)
    connector = AwsStsConnector(region="us-east-1", client=client)
    with pytest.raises(expected):
        connector.mint(REQUEST)
    assert client.calls == 1  # a lost response is an orphan-session hazard: exactly one attempt


class _StaticClient:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response

    def assume_role(self, **_: Any) -> dict[str, Any]:
        return self.response


def test_expiration_that_does_not_match_the_ttl_is_a_protocol_error() -> None:
    wrong = _ok_response(duration=3600)  # asked 1800, got 3600
    with pytest.raises(ProtocolError, match="does not match"):
        AwsStsConnector(region="us-east-1", client=_StaticClient(wrong)).mint(REQUEST)
    missing = {"Credentials": {"AccessKeyId": "ASIA", "SecretAccessKey": "s"}}
    with pytest.raises(ProtocolError, match="missing"):
        AwsStsConnector(region="us-east-1", client=_StaticClient(missing)).mint(REQUEST)


def test_registration_validation() -> None:
    connector = AwsStsConnector(region="us-east-1", client=_StaticClient({}))
    connector.validate_registration(ARN, None)
    with pytest.raises(ValueError, match="well-formed"):
        connector.validate_registration("arn:aws:iam::1:role/x", None)
    with pytest.raises(ValueError, match="A1"):
        connector.validate_registration(ARN, "ext")
