import pytest

from keystone.config.settings import Settings, SettingsError

BASE = {
    "KEYSTONE_DATABASE_URL": "postgresql+psycopg://u:p@h/db",
    "KEYSTONE_REDIS_URL": "redis://r:6379/0",
    "KEYSTONE_AWS_REGION": "eu-west-1",
    "KEYSTONE_OIDC_AUDIENCE": "keystone-acme",
}


def test_env_over_defaults_and_ignores_foreign_keys() -> None:
    settings = Settings.from_env(
        {**BASE, "PATH": "/bin", "KEYSTONE_STS_READ_TIMEOUT_SECONDS": "2.5"}
    )
    assert settings.aws_region == "eu-west-1"
    assert settings.sts_read_timeout_seconds == 2.5
    assert settings.sts_connect_timeout_seconds == 3.0
    assert settings.effective_aggregation_redis_url == "redis://r:6379/0"
    assert settings.revocation_put_role_policy_enabled is False


@pytest.mark.parametrize(
    "bad",
    [
        {"KEYSTONE_AWS_REGION": "US-EAST-1"},
        {"KEYSTONE_STS_READ_TIMEOUT_SECONDS": "0"},
        {"KEYSTONE_STS_READ_TIMEOUT_SECONDS": "60"},
        {"KEYSTONE_UNKNOWN_KNOB": "1"},
        {"KEYSTONE_OPA_URL": "http://opa.internal:8181"},
        {"KEYSTONE_OIDC_ISSUER": "http://token.actions.githubusercontent.com"},
    ],
)
def test_refuses_to_start_on_invalid_or_unknown_settings(bad: dict[str, str]) -> None:
    with pytest.raises(SettingsError, match="KEYSTONE_"):
        Settings.from_env({**BASE, **bad})


def test_test_only_variables_do_not_block_boot() -> None:
    # The documented local run exports these next to the real settings (HANDOFF "How to run").
    settings = Settings.from_env(
        {
            **BASE,
            "KEYSTONE_TEST_DATABASE_URL": "postgresql+psycopg://t:t@h/test",
            "KEYSTONE_TEST_REDIS_URL": "redis://t:6379/0",
            "KEYSTONE_OPA_BIN": "/usr/local/bin/opa",
        }
    )
    assert settings.redis_url == "redis://r:6379/0"


def test_missing_required_settings_fail_loud() -> None:
    with pytest.raises(SettingsError, match="KEYSTONE_AWS_REGION"):
        Settings.from_env({k: v for k, v in BASE.items() if k != "KEYSTONE_AWS_REGION"})


def test_operational_secrets_never_render() -> None:
    secret = "b" * 40
    settings = Settings.from_env(
        {**BASE, "KEYSTONE_ADMIN_BOOTSTRAP_TOKEN": secret, "KEYSTONE_BUNDLE_SERVICE_TOKEN": secret}
    )
    assert settings.admin_bootstrap_token is not None
    assert settings.admin_bootstrap_token.get_secret_value() == secret
    assert secret not in repr(settings) and secret not in str(settings)


def test_short_operational_secrets_refuse_boot() -> None:
    with pytest.raises(SettingsError, match="KEYSTONE_ADMIN_BOOTSTRAP_TOKEN"):
        Settings.from_env({**BASE, "KEYSTONE_ADMIN_BOOTSTRAP_TOKEN": "short"})
