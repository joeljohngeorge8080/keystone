"""AwsStsConnector — spec Ch. 23. Region-pinned AssumeRole with explicit, never-blind retry."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    ReadTimeoutError,
)

from keystone.broker.connectors.base import (
    ROLE_ARN_MAX_LEN,
    ROLE_ARN_PATTERN,
    AccessDeniedError,
    ConnectorCapabilities,
    IndeterminateError,
    IssuedCredential,
    MintRequest,
    ProtocolError,
    TemplateError,
    UnavailableError,
)

EXPIRATION_TOLERANCE = timedelta(seconds=120)
_BROKER_CREDENTIAL_CODES = frozenset(
    {"InvalidClientTokenId", "ExpiredToken", "UnrecognizedClientException", "AuthFailure"}
)


class AwsStsConnector:
    def __init__(
        self,
        *,
        region: str,
        endpoint_url: str | None = None,
        connect_timeout: float = 3.0,
        read_timeout: float = 5.0,
        client: Any | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        # botocore must never retry on its own: a retried timeout can mint two sessions where
        # the audit record knows about one. The connector retries Throttling exactly once.
        config = Config(
            region_name=region,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries={"total_max_attempts": 1, "mode": "standard"},
        )
        self._client = client or boto3.client("sts", config=config, endpoint_url=endpoint_url)
        self._clock = clock

    def describe_capabilities(self) -> ConnectorCapabilities:
        return ConnectorCapabilities(
            provider="aws-sts",
            max_duration_seconds=3600,
            supports_session_policy=True,
            supports_tags=True,
            supports_external_id=True,
        )

    def validate_registration(self, role_arn: str, external_id: str | None) -> None:
        if len(role_arn) > ROLE_ARN_MAX_LEN or not re.fullmatch(ROLE_ARN_PATTERN, role_arn):
            raise ValueError("role_arn is not a well-formed IAM role ARN")
        if external_id is not None:
            raise ValueError("cross-account external_id is a reserved extension point (A1)")

    def mint(self, request: MintRequest) -> IssuedCredential:
        params: dict[str, Any] = {
            "RoleArn": request.role_arn,
            "RoleSessionName": request.session_name,
            "DurationSeconds": request.duration_seconds,
        }
        if request.session_policy is not None:
            params["Policy"] = json.dumps(request.session_policy, separators=(",", ":"))
        if request.tags:
            params["Tags"] = [{"Key": k, "Value": v} for k, v in sorted(request.tags.items())]
        if request.external_id is not None:
            params["ExternalId"] = request.external_id

        started = self._clock()
        response = self._assume_role(params, allow_throttle_retry=True)
        return self._parse(response, started, request.duration_seconds)

    def _assume_role(self, params: dict[str, Any], *, allow_throttle_retry: bool) -> dict[str, Any]:
        try:
            result: dict[str, Any] = self._client.assume_role(**params)
            return result
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in {"AccessDenied", "AccessDeniedException"}:
                raise AccessDeniedError(f"STS AccessDenied for {params['RoleArn']}") from exc
            if code == "MalformedPolicyDocument":
                raise TemplateError("session policy template rejected by STS") from exc
            if code in {"Throttling", "ThrottlingException", "TooManyRequestsException"}:
                if allow_throttle_retry:
                    return self._assume_role(params, allow_throttle_retry=False)
                raise UnavailableError("STS throttled twice") from exc
            if code in _BROKER_CREDENTIAL_CODES:
                raise UnavailableError(f"broker credentials rejected: {code}") from exc
            if code == "RegionDisabledException":
                raise UnavailableError("STS region disabled") from exc
            # Unknown client error class: the call was answered, so no orphan session hazard.
            raise UnavailableError(f"STS error {code or 'unknown'}") from exc
        except NoCredentialsError as exc:
            raise UnavailableError("broker has no AWS credentials") from exc
        except (ConnectTimeoutError, EndpointConnectionError) as exc:
            # Connection never established: STS did not see the request.
            raise UnavailableError("STS endpoint unreachable") from exc
        except (ReadTimeoutError, ConnectionClosedError) as exc:
            # Request may have been processed: a live session may exist. No retry.
            raise IndeterminateError("STS response lost after send") from exc

    def _parse(
        self, response: dict[str, Any], started: datetime, duration: int
    ) -> IssuedCredential:
        creds = response.get("Credentials") or {}
        try:
            credential = IssuedCredential(
                access_key_id=str(creds["AccessKeyId"]),
                secret_access_key=str(creds["SecretAccessKey"]),
                session_token=str(creds["SessionToken"]),
                expiration=creds["Expiration"],
            )
        except KeyError as exc:
            raise ProtocolError(f"STS response missing {exc}") from exc
        if credential.expiration.tzinfo is None:
            raise ProtocolError("STS Expiration is not timezone-aware")
        expected = started + timedelta(seconds=duration)
        if abs(credential.expiration - expected) > EXPIRATION_TOLERANCE:
            raise ProtocolError("STS Expiration does not match the granted TTL")
        return credential
