"""CLI transport rules (Ch. 45): TLS only, token from env/file and never argv, safe output."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from keystone_cli.client import AdminClient, UsageError, check_admin_url, read_token
from keystone_cli.main import main
from keystone_cli.output import safe, write_table

TOKEN = "t" * 40


@pytest.mark.parametrize(
    "url",
    ["https://keystone-admin.internal:8443", "http://127.0.0.1:8081", "http://localhost:8081/"],
)
def test_tls_or_loopback_tunnel_urls_are_accepted(url: str) -> None:
    assert not check_admin_url(url).endswith("/")


@pytest.mark.parametrize(
    "url", ["http://keystone-admin.internal", "ftp://x", "https://", "keystone-admin:8443"]
)
def test_plaintext_or_malformed_urls_are_refused(url: str) -> None:
    with pytest.raises(UsageError, match="https://"):
        check_admin_url(url)


def test_token_from_env_or_file_but_not_both(tmp_path: Path) -> None:
    assert read_token({"KEYSTONE_ADMIN_TOKEN": TOKEN}) == TOKEN
    path = tmp_path / "token"
    path.write_text(TOKEN + "\n")
    assert read_token({"KEYSTONE_ADMIN_TOKEN_FILE": str(path)}) == TOKEN
    with pytest.raises(UsageError, match="only one"):
        read_token({"KEYSTONE_ADMIN_TOKEN": TOKEN, "KEYSTONE_ADMIN_TOKEN_FILE": str(path)})
    with pytest.raises(UsageError, match="never passed on argv"):
        read_token({})
    with pytest.raises(UsageError, match="cannot read"):
        read_token({"KEYSTONE_ADMIN_TOKEN_FILE": str(tmp_path / "missing")})


def test_there_is_no_token_flag() -> None:
    with pytest.raises(SystemExit) as info:
        main(["roles", "list", "--token", TOKEN], io.StringIO())
    assert info.value.code == 2


def test_missing_configuration_is_exit_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("KEYSTONE_ADMIN_URL", raising=False)
    assert main(["roles", "list"], io.StringIO()) == 2
    assert "KEYSTONE_ADMIN_URL is not set" in capsys.readouterr().err


def test_client_repr_never_shows_the_token() -> None:
    client = AdminClient.from_env(
        {"KEYSTONE_ADMIN_URL": "https://admin.internal", "KEYSTONE_ADMIN_TOKEN": TOKEN}
    )
    assert TOKEN not in repr(client)


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("main", "main"),
        ("\x1b[2J\x1b[Hfake", "\\x1b[2J\\x1b[Hfake"),  # clear-screen + cursor-home
        ("a\nFORGED LINE", "a\\x0aFORGED LINE"),
        ("abc" + chr(0x202E) + "dcba", "abc\\u202edcba"),  # right-to-left override
        ("x" + chr(0x2028) + "y", "x\\u2028y"),  # line separator
        ("\x9b31m", "\\x9b31m"),  # 8-bit CSI
        ("ünïcode ok", "ünïcode ok"),
        (None, ""),
    ],
)
def test_hostile_text_is_escaped_for_the_terminal(raw: str | None, shown: str) -> None:
    assert safe(raw) == shown


def test_long_cells_are_truncated_and_tables_align() -> None:
    out = io.StringIO()
    write_table(out, [{"a": "x" * 200, "b": 1}, {"a": "y", "b": 22}], ("a", "b"))
    header, first, second = out.getvalue().splitlines()
    assert len(first.split()[0]) == 72 and first.split()[0].endswith("…")
    assert header.index("B") == first.index("1") == second.index("22")
