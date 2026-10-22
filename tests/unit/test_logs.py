"""Structured logging (Ch. 49): JSON lines, request correlation, the serializer denylist."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from keystone.api.app import create_app
from keystone.telemetry.logs import (
    REDACTED,
    JsonFormatter,
    decision_id_var,
    redact,
    request_id_var,
)
from tests.unit.test_api_http import GOOD, FakePipeline, _post


@pytest.fixture
def captured() -> Iterator[tuple[logging.Logger, io.StringIO]]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter("public"))
    logger = logging.getLogger("keystone.test.logs")
    logger.handlers[:] = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    yield logger, stream
    logger.handlers[:] = []


def _lines(stream: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_one_json_object_per_line_with_plane_and_component(
    captured: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured
    logger.info("issued %s", "ok", extra={"grant": "deploy-prod"})
    (line,) = _lines(stream)
    assert line["level"] == "INFO" and line["plane"] == "public"
    assert line["component"] == "keystone.test.logs" and line["message"] == "issued ok"
    assert line["grant"] == "deploy-prod" and "ts" in line


def test_request_and_decision_ids_come_from_context(
    captured: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured
    r, d = request_id_var.set("req-1"), decision_id_var.set("dec-1")
    try:
        logger.warning("inside a request")
    finally:
        request_id_var.reset(r)
        decision_id_var.reset(d)
    logger.warning("outside")
    inside, outside = _lines(stream)
    assert inside["request_id"] == "req-1" and inside["decision_id"] == "dec-1"
    assert "request_id" not in outside and "decision_id" not in outside


@pytest.mark.parametrize(
    "field",
    [
        "token",
        "admin_token",
        "secret_access_key",
        "session_token",
        "Authorization",
        "password",
        "private_key",
        "api_key",
        "cookie",
    ],
)
def test_denylisted_fields_are_redacted_at_any_depth(
    captured: tuple[logging.Logger, io.StringIO], field: str
) -> None:
    logger, stream = captured
    logger.info("x", extra={field: "LEAK", "nested": {"inner": [{field: "LEAK"}]}})
    text = stream.getvalue()
    assert "LEAK" not in text
    (line,) = _lines(stream)
    assert line[field] == REDACTED


def test_ordinary_fields_survive_redaction() -> None:
    assert redact({"grant": "g", "keyset": [1, 2], "monkey": "m", "jwks_kid": "k"}) == {
        "grant": "g",
        "keyset": [1, 2],
        "monkey": "m",
        "jwks_kid": "k",
    }


def test_exceptions_log_type_and_frames_but_never_their_message(
    captured: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured
    try:
        raise RuntimeError("password=hunter2 [parameters: {'jti': 'abc'}]")
    except RuntimeError:
        logger.exception("failed")
    (line,) = _lines(stream)
    assert line["exception"] == "RuntimeError"
    assert any("test_logs.py" in str(frame) for frame in line["frames"])  # type: ignore[attr-defined]
    assert "hunter2" not in stream.getvalue() and "abc" not in stream.getvalue()


def test_request_id_in_logs_matches_the_response_header() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter("public"))
    probe = logging.getLogger("keystone.test.pipeline")
    probe.handlers[:] = [handler]
    probe.propagate = False
    probe.setLevel(logging.INFO)

    class LoggingPipeline(FakePipeline):
        def handle(self, request, *, source_ip, request_id):  # type: ignore[no-untyped-def]
            probe.info("handling")  # runs in a worker thread with a copied context
            return super().handle(request, source_ip=source_ip, request_id=request_id)

    client = TestClient(create_app(LoggingPipeline()), raise_server_exceptions=False)
    response = _post(client, GOOD)
    (line,) = _lines(stream)
    assert line["request_id"] == response.headers["x-request-id"]
