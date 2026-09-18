from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from keystone.broker.connectors.base import INLINE_POLICY_MAX_CHARS, IssuedCredential, MintRequest

ARN = "arn:aws:iam::123456789012:role/keystone/deploy-prod"


def _request(**overrides: object) -> MintRequest:
    base: dict[str, object] = {
        "role_arn": ARN,
        "session_name": "ks-1-2-3",
        "duration_seconds": 900,
        "tags": {"keystone:decision_id": "abc", "keystone:repository": "acme/app"},
    }
    base.update(overrides)
    return MintRequest(**base)  # type: ignore[arg-type]


def test_minimal_request_is_valid() -> None:
    request = _request()
    assert request.session_policy is None and request.external_id is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"role_arn": "arn:aws:iam::12345:role/x"},  # account id must be 12 digits
        {"role_arn": "arn:aws:iam::123456789012:user/x"},  # users are never brokered (A6)
        {"session_name": "x"},  # too short
        {"session_name": "has space"},
        {"duration_seconds": 899},
        {"duration_seconds": 3601},
        {"duration_seconds": "900"},  # strict: no coercion
        {"tags": {"env": "prod"}},  # not in the closed attribution set
        {"tags": {"keystone:actor": "bad;value"}},
        {"tags": {"keystone:actor": "x" * 257}},
        {"external_id": "x"},
        {"unknown": 1},
    ],
)
def test_hostile_or_malformed_requests_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _request(**overrides)


def test_inline_policy_size_is_capped_at_sts_limit() -> None:
    small = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
    assert _request(session_policy=small).session_policy == small
    huge = {"Version": "2012-10-17", "Statement": [{"Sid": "x" * INLINE_POLICY_MAX_CHARS}]}
    with pytest.raises(ValidationError, match="exceeds"):
        _request(session_policy=huge)


def test_issued_credential_never_reveals_secret_material() -> None:
    credential = IssuedCredential(
        access_key_id="ASIAEXAMPLE12345678",
        secret_access_key="topsecret",
        session_token="tok",
        expiration=datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
    )
    text = f"{credential!r} {credential} {[credential]}"
    assert "topsecret" not in text and "tok" not in text.split("prefix")[1]
    assert credential.access_key_prefix == "ASIAEXAM"
    assert "ASIAEXAMPLE12345678" not in text
