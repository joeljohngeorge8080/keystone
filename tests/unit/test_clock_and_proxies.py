"""Clock-sync classification (Ch. 31) and trusted-proxy source address resolution (Ch. 62)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from keystone.api.app import create_app
from keystone.api.http import client_ip, parse_networks
from keystone.config.settings import Settings, SettingsError
from keystone.telemetry.clock import (
    DESYNCED,
    MAX_DESYNC_MICROSECONDS,
    SYNCED,
    UNKNOWN,
    UNSYNCED,
    clock_sync_state,
    kernel_clock_state,
)
from tests.unit.test_api_http import GOOD, FakePipeline, _post
from tests.unit.test_settings import BASE


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ((0, 80_000), SYNCED),
        ((0, MAX_DESYNC_MICROSECONDS), SYNCED),
        ((0, MAX_DESYNC_MICROSECONDS + 1), DESYNCED),
        ((5, 0), UNSYNCED),  # TIME_ERROR: the kernel says the clock is not disciplined
        (None, UNKNOWN),
    ],
)
def test_clock_sync_classification(state: tuple[int, int] | None, expected: str) -> None:
    assert clock_sync_state(lambda: state) == expected


def test_clock_sync_read_failure_is_unknown_not_ok() -> None:
    def broken() -> tuple[int, int] | None:
        raise OSError("no adjtimex")

    assert clock_sync_state(broken) == UNKNOWN


def test_kernel_clock_state_reads_without_privilege() -> None:
    state = kernel_clock_state()
    assert state is None or (state[0] >= 0 and state[1] >= 0)


class RecordingPipeline(FakePipeline):
    def __init__(self) -> None:
        super().__init__()
        self.source_ips: list[str] = []

    def handle(self, request: Any, *, source_ip: str, request_id: str) -> Any:
        self.source_ips.append(source_ip)
        return super().handle(request, source_ip=source_ip, request_id=request_id)


def _source_ip(trusted: str, forwarded: str | None) -> str:
    pipeline = RecordingPipeline()
    client = TestClient(
        create_app(pipeline, trusted_proxies=parse_networks(trusted)),
        raise_server_exceptions=False,
    )
    headers = {} if forwarded is None else {"X-Forwarded-For": forwarded}
    assert _post(client, GOOD, headers=headers).status_code == 201
    return pipeline.source_ips[0]


# End to end through the app: TestClient's peer is "testclient", never a trusted proxy.
@pytest.mark.parametrize(
    ("trusted", "forwarded", "expected"),
    [
        ("", "203.0.113.9", "testclient"),  # no trusted proxies: header ignored entirely
        ("10.0.0.0/8", "203.0.113.9", "testclient"),  # peer is not a trusted proxy
    ],
)
def test_untrusted_peers_cannot_choose_their_address(
    trusted: str, forwarded: str | None, expected: str
) -> None:
    assert _source_ip(trusted, forwarded) == expected


@pytest.mark.parametrize(
    ("forwarded", "expected"),
    [
        ("203.0.113.9", "203.0.113.9"),
        ("198.51.100.1, 203.0.113.9, 10.0.0.2", "203.0.113.9"),  # rightmost untrusted hop
        ("spoofed-by-client, 203.0.113.9", "203.0.113.9"),
        ("203.0.113.9, not-an-ip", "proxy"),  # malformed nearest hop: fall back to the peer
        (None, "proxy"),
    ],
)
def test_trusted_proxy_header_walk(forwarded: str | None, expected: str) -> None:
    headers = [] if forwarded is None else [(b"x-forwarded-for", forwarded.encode())]
    scope = {"type": "http", "headers": headers, "client": ("10.0.0.1", 443)}
    resolved = client_ip(Request(scope), parse_networks("10.0.0.0/8"))
    assert resolved == ("10.0.0.1" if expected == "proxy" else expected)


@pytest.mark.parametrize("bad", ["10.0.0.0/33", "not-a-cidr", "10.0.0.1/8"])
def test_bad_trusted_proxy_setting_refuses_boot(bad: str) -> None:
    with pytest.raises(SettingsError, match="KEYSTONE_TRUSTED_PROXIES"):
        Settings.from_env({**BASE, "KEYSTONE_TRUSTED_PROXIES": bad})
