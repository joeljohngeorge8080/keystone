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
    aws_region: str = Field(pattern=r"^[a-z]{2}-[a-z]+-[0-9]$")
    sts_endpoint_url: str | None = None
    sts_connect_timeout_seconds: float = Field(default=3.0, gt=0, le=10)
    sts_read_timeout_seconds: float = Field(default=5.0, gt=0, le=30)

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> Settings:
        raw = {
            key[len(ENV_PREFIX) :].lower(): value
            for key, value in environ.items()
            if key.startswith(ENV_PREFIX)
        }
        # Test-only variables share the prefix but are not settings.
        raw.pop("test_database_url", None)
        raw.pop("opa_bin", None)
        try:
            return cls(**raw)
        except ValidationError as exc:
            problems = "; ".join(
                f"{ENV_PREFIX}{'.'.join(str(p) for p in e['loc']).upper()}: {e['msg']}"
                for e in exc.errors()
            )
            raise SettingsError(f"invalid configuration: {problems}") from exc
