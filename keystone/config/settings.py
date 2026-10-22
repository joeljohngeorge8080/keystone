"""Boot-time settings (Ch. 47): env > defaults, frozen, refuse to start on unknown keys."""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError

ENV_PREFIX = "KEYSTONE_"


class SettingsError(Exception):
    pass


class Settings(BaseModel):
    model_config = ConfigDict(strict=False, frozen=True, extra="forbid")

    database_url: str = Field(min_length=1)
    redis_url: str = Field(min_length=1)
    aggregation_redis_url: str | None = None  # separate instance with its own memory budget (R4)
    celery_broker_url: str | None = None  # defaults to redis_url
    aws_region: str = Field(pattern=r"^[a-z]{2}-[a-z]+-[0-9]$")
    sts_endpoint_url: str | None = None
    sts_connect_timeout_seconds: float = Field(default=3.0, gt=0, le=10)
    sts_read_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    oidc_issuer: str = Field(
        default="https://token.actions.githubusercontent.com", pattern=r"^https://"
    )
    oidc_audience: str = Field(min_length=1, max_length=256)
    jwks_url: str = Field(
        default="https://token.actions.githubusercontent.com/.well-known/jwks", pattern=r"^https://"
    )
    opa_url: str = Field(
        default="http://127.0.0.1:8181", pattern=r"^http://(127\.0\.0\.1|localhost)"
    )
    anchor_key_pem_path: str | None = (
        None  # host-injected Ed25519 key (A8); never in DB or env value
    )
    anchor_bucket: str | None = None
    anchor_breaker_threshold_seconds: int = Field(default=600, ge=60, le=86400)
    revocation_put_role_policy_enabled: bool = False  # Ch. 26 mechanism 3, default OFF
    keystone_version: str = Field(default="0.1.0", min_length=1)

    @property
    def effective_aggregation_redis_url(self) -> str:
        return self.aggregation_redis_url or self.redis_url

    @property
    def effective_celery_broker_url(self) -> str:
        return self.celery_broker_url or self.redis_url

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> Settings:
        # Test-only variables share the prefix but are not settings: KEYSTONE_TEST_* is a reserved
        # namespace no setting may use, so any other unknown key still refuses boot.
        raw = {
            key[len(ENV_PREFIX) :].lower(): value
            for key, value in environ.items()
            if key.startswith(ENV_PREFIX) and not key.startswith(ENV_PREFIX + "TEST_")
        }
        raw.pop("opa_bin", None)
        try:
            return cls(**raw)
        except ValidationError as exc:
            problems = "; ".join(
                f"{ENV_PREFIX}{'.'.join(str(p) for p in e['loc']).upper()}: {e['msg']}"
                for e in exc.errors()
            )
            raise SettingsError(f"invalid configuration: {problems}") from exc
