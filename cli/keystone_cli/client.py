"""Admin-plane HTTP client for the operator CLI (Ch. 45).

The bearer comes from `KEYSTONE_ADMIN_TOKEN` or a file named by `KEYSTONE_ADMIN_TOKEN_FILE`,
never from argv (argv is visible to every local user via the process table and lands in shell
history). The admin plane is reached over TLS; plain http is accepted only for a loopback
address, where a port-forward or SSH tunnel already provides the transport security.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

ADMIN_URL_ENV = "KEYSTONE_ADMIN_URL"
TOKEN_ENV = "KEYSTONE_ADMIN_TOKEN"  # noqa: S105 — variable name, not a secret
TOKEN_FILE_ENV = "KEYSTONE_ADMIN_TOKEN_FILE"  # noqa: S105
CA_BUNDLE_ENV = "KEYSTONE_ADMIN_CA_BUNDLE"
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
DEFAULT_TIMEOUT_SECONDS = 30.0


class UsageError(Exception):
    """Bad invocation or configuration: exit 2."""


@dataclass(frozen=True)
class ApiFailure(Exception):
    """The admin plane answered with its error envelope (Ch. 43): exit 2."""

    status: int
    code: str
    message: str
    request_id: str | None

    def __str__(self) -> str:
        rid = f" [request {self.request_id}]" if self.request_id else ""
        return f"{self.code} (HTTP {self.status}): {self.message}{rid}"


def check_admin_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url.rstrip("/")
    if parts.scheme == "http" and parts.hostname in _LOOPBACK:
        return url.rstrip("/")
    raise UsageError(
        f"{ADMIN_URL_ENV} must be an https:// URL (plain http only for a loopback tunnel)"
    )


def read_token(environ: Mapping[str, str]) -> str:
    token = environ.get(TOKEN_ENV)
    path = environ.get(TOKEN_FILE_ENV)
    if token and path:
        raise UsageError(f"set only one of {TOKEN_ENV} and {TOKEN_FILE_ENV}")
    if path:
        try:
            with open(path, encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            raise UsageError(f"cannot read {TOKEN_FILE_ENV}: {exc.strerror}") from exc
    if not token:
        raise UsageError(
            f"no admin token: set {TOKEN_ENV} or {TOKEN_FILE_ENV} (never passed on argv)"
        )
    return token


class AdminClient:
    def __init__(self, base_url: str, token: str, http: httpx.Client) -> None:
        self._base = base_url
        self._token = token
        self._http = http

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> AdminClient:
        env = os.environ if environ is None else environ
        url = env.get(ADMIN_URL_ENV)
        if not url:
            raise UsageError(f"{ADMIN_URL_ENV} is not set")
        base = check_admin_url(url)
        verify: str | bool = env.get(CA_BUNDLE_ENV) or True
        http = httpx.Client(timeout=DEFAULT_TIMEOUT_SECONDS, verify=verify, follow_redirects=False)
        return cls(base, read_token(env), http)

    def __repr__(self) -> str:
        return f"AdminClient({self._base!r}, token=<redacted>)"

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        content: bytes | None = None,
        content_type: str | None = None,
    ) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        if content_type is not None:
            headers["Content-Type"] = content_type
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            response = self._http.request(
                method,
                self._base + path,
                params=clean,
                json=json,
                content=content,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise UsageError(f"cannot reach the admin plane: {type(exc).__name__}") from exc
        try:
            body = response.json()
        except ValueError:
            body = None
        if response.status_code >= 400:
            error = body.get("error") if isinstance(body, dict) else None
            if not isinstance(error, dict):
                error = {}
            raise ApiFailure(
                status=response.status_code,
                code=str(error.get("code", "HTTP_ERROR")),
                message=str(error.get("message", "request failed")),
                request_id=response.headers.get("x-request-id"),
            )
        if not isinstance(body, dict):
            raise UsageError("the admin plane returned a non-JSON response")
        return body
