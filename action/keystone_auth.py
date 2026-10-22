"""keystone-auth (Ch. 46): exchange the job's GitHub OIDC token for short-lived AWS credentials.

Standard library only (dependency-minimal); runs on the runner's python3 (3.10+).

Flow per attempt: request a FRESH OIDC token (the broker consumes each JTI exactly once) ->
POST {keystone_url}/v1/credentials -> on 201 mask all three credential values BEFORE anything else
is printed or exported, then export AWS_* and KEYSTONE_DECISION_ID; on 403 print the decision's
explanation and fail; on 429/503 (or a network error) back off 2/4/8 s and retry, up to `retry`
attempts; every other 4xx/5xx is terminal.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

RETRYABLE = (429, 503)
BACKOFF_SECONDS = (2, 4, 8)
MAX_RETRY_AFTER_SECONDS = 30
TIMEOUT_SECONDS = 15
GRANT = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_LOOPBACK = ("localhost", "127.0.0.1", "::1")
# What a credential value may contain before it is written to GITHUB_ENV.
_CREDENTIAL_VALUE = re.compile(r"^[A-Za-z0-9+/=_.:-]{1,4096}$")


class ActionError(Exception):
    """A terminal failure: the message is printed as a workflow error."""


def _input(name: str, default: str | None = None) -> str:
    # The runner exposes `inputs.x` to composite steps through the env block in action.yml.
    value = os.environ.get("INPUT_" + name.upper(), "").strip()
    if value:
        return value
    if default is None:
        raise ActionError(f"input '{name}' is required")
    return default


def check_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url.rstrip("/")
    if parts.scheme == "http" and parts.hostname in _LOOPBACK:
        return url.rstrip("/")
    raise ActionError("keystone_url must be an https:// URL")


def fetch_oidc_token(audience: str | None, opener: Callable[..., Any]) -> str:
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not request_url or not request_token:
        raise ActionError("no OIDC token available: the job needs `permissions: id-token: write`")
    url = request_url
    if audience:
        sep = "&" if "?" in url else "?"
        url += sep + urllib.parse.urlencode({"audience": audience})
    request = urllib.request.Request(url, headers={"Authorization": "bearer " + request_token})  # noqa: S310 — scheme checked by check_url
    with opener(request, timeout=TIMEOUT_SECONDS) as response:
        value = json.loads(response.read().decode("utf-8")).get("value")
    if not isinstance(value, str) or not value:
        raise ActionError("the OIDC token response carried no token")
    return value


def post_credentials(
    base: str, body: dict[str, Any], opener: Callable[..., Any]
) -> tuple[int, dict[str, Any], dict[str, str]]:
    request = urllib.request.Request(  # noqa: S310
        base + "/v1/credentials",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with opener(request, timeout=TIMEOUT_SECONDS) as response:
            status, raw, headers = response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        status, raw, headers = exc.code, exc.read(), dict(exc.headers or {})
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except ValueError:
        parsed = {}
    return status, parsed if isinstance(parsed, dict) else {}, headers


def mask(value: str, out: Any) -> None:
    out.write(f"::add-mask::{value}\n")
    out.flush()


def _export(path: str, name: str, value: str) -> None:
    # Heredoc form with a random delimiter: a value can never close it and inject variables.
    delimiter = "ghadelim_" + secrets.token_hex(16)
    if delimiter in value or "\n" in value or "\r" in value:
        raise ActionError(f"refusing to export {name}: unexpected characters")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")


def deliver(body: dict[str, Any], out: Any) -> None:
    credentials = body.get("credentials")
    if not isinstance(credentials, dict):
        raise ActionError("the broker answered 201 without credentials")
    values = {
        "AWS_ACCESS_KEY_ID": credentials.get("access_key_id"),
        "AWS_SECRET_ACCESS_KEY": credentials.get("secret_access_key"),
        "AWS_SESSION_TOKEN": credentials.get("session_token"),
    }
    # Masking precedes any other statement that could print or persist a value (Ch. 46).
    for value in values.values():
        if isinstance(value, str) and value:
            mask(value, out)
    for name, value in values.items():
        if not isinstance(value, str) or not _CREDENTIAL_VALUE.match(value):
            raise ActionError(f"the broker returned a malformed {name}")
    env_file = os.environ.get("GITHUB_ENV")
    if not env_file:
        raise ActionError("GITHUB_ENV is not set; not running inside GitHub Actions?")
    for name, value in values.items():
        _export(env_file, name, value)
    decision_id = str(body.get("decision_id", ""))
    region = str(body.get("region_hint", ""))
    _export(env_file, "KEYSTONE_DECISION_ID", decision_id)
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        _export(output_file, "decision_id", decision_id)
    if re.match(r"^[a-z]{2}-[a-z]+-[0-9]$", region):
        _export(env_file, "AWS_REGION", region)
    out.write(
        f"keystone: credentials for grant '{body.get('grant')}' "
        f"(decision {decision_id}, ttl {body.get('granted_ttl_seconds')}s"
        f"{', clamped' if body.get('ttl_clamped') else ''})\n"
    )


def _denied(body: dict[str, Any]) -> str:
    error = body.get("error") or {}
    reasons = ", ".join(str(r) for r in error.get("reasons") or []) or "none given"
    return (
        f"policy denied the request (decision {body.get('decision_id')}): reasons: {reasons}; "
        f"rule: {error.get('rule_path')}; policy: {error.get('policy_digest')}"
    )


def _retry_delay(attempt: int, headers: dict[str, str]) -> float:
    delay = float(BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS) - 1)])
    advertised = {k.lower(): v for k, v in headers.items()}.get("retry-after", "")
    if advertised.isdigit():
        delay = max(delay, min(float(advertised), MAX_RETRY_AFTER_SECONDS))
    return delay


def run(
    out: Any = sys.stdout,
    opener: Callable[..., Any] = urllib.request.urlopen,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    base = check_url(_input("keystone_url"))
    grant = _input("grant")
    if not GRANT.match(grant):
        raise ActionError("grant must match ^[a-z0-9][a-z0-9-]{1,63}$")
    ttl_raw = _input("ttl_seconds", "")
    attempts = int(_input("retry", "3")) + 1
    if not 1 <= attempts <= 10:
        raise ActionError("retry must be between 0 and 9")
    audience = _input("audience", "") or None

    last = "no attempt made"
    for attempt in range(attempts):
        body: dict[str, Any] = {"token": fetch_oidc_token(audience, opener), "grant": grant}
        if ttl_raw:
            body["ttl_seconds"] = int(ttl_raw)
        try:
            status, reply, headers = post_credentials(base, body, opener)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            status, reply, headers = 0, {}, {}
            last = f"network error: {type(exc).__name__}"
        if status == 201:
            deliver(reply, out)
            return 0
        if status == 403:
            raise ActionError(_denied(reply))
        error = reply.get("error") or {}
        if status:
            last = f"HTTP {status} {error.get('code', '')}: {error.get('message', '')}".strip()
        if status and status not in RETRYABLE:
            raise ActionError(last)
        if attempt + 1 < attempts:
            delay = _retry_delay(attempt, headers)
            out.write(f"keystone: {last}; retrying in {delay:.0f}s with a fresh OIDC token\n")
            sleep(delay)
    raise ActionError(f"giving up after {attempts} attempts: {last}")


def main() -> int:
    try:
        return run()
    except ActionError as exc:
        sys.stdout.write(f"::error title=keystone-auth::{exc}\n")
        return 1
    except ValueError as exc:
        sys.stdout.write(f"::error title=keystone-auth::invalid input: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
