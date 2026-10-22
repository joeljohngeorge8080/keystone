"""HTTP plumbing shared by the public and admin planes (Ch. 39, 41, 43).

Every response carries `X-Request-Id` and `Cache-Control: no-store`; every error uses the one
envelope; unknown routes and unexpected failures never leak framework or exception text.
JSON bodies are read under a byte cap, strict UTF-8, with duplicate keys and non-finite numbers
refused, and validated without echoing hostile input back.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, JsonValue, ValidationError
from starlette.background import BackgroundTask
from starlette.exceptions import HTTPException as StarletteHTTPException

from keystone.api.errors import KNOWN_ERRORS, ApiError, envelope, map_exception, rejected
from keystone.db.ids import uuid7


def json_response(
    status: int,
    content: dict[str, JsonValue],
    *,
    headers: dict[str, str] | None = None,
    background: BackgroundTask | None = None,
) -> JSONResponse:
    return JSONResponse(status_code=status, content=content, headers=headers, background=background)


def error_response(error: ApiError, request_id: str) -> JSONResponse:
    headers = None
    if error.retry_after_seconds is not None:
        headers = {"Retry-After": str(error.retry_after_seconds)}
    return json_response(error.status, envelope(error, request_id), headers=headers)


def request_id_of(request: Request) -> str:
    return str(getattr(request.state, "request_id", "unknown"))


def install_common(app: FastAPI, log: logging.Logger, *, map_known_errors: bool = False) -> None:
    """Request-id + no-store middleware, the 404/405 envelope and the generic 500.

    `map_known_errors` also turns every KNOWN_ERRORS exception escaping a route into its mapped
    envelope (the admin plane's routes rely on this; the public route maps explicitly).
    """

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.request_id = str(uuid7())
        response = await call_next(request)
        response.headers["X-Request-Id"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}.get(exc.status_code, "HTTP_ERROR")
        error = ApiError(exc.status_code, code, "no such route or method", False)
        return error_response(error, request_id_of(request))

    @app.exception_handler(RequestValidationError)
    async def invalid_parameters(request: Request, exc: RequestValidationError) -> JSONResponse:
        problems: list[JsonValue] = [
            {"field": ".".join(str(p) for p in e.get("loc", ())) or "$", "error": e.get("type")}
            for e in exc.errors()
        ]
        error = ApiError(
            400, "VALIDATION_FAILED", "request failed validation", False, {"problems": problems}
        )
        return error_response(error, request_id_of(request))

    if map_known_errors:

        async def known(request: Request, exc: Exception) -> JSONResponse:
            return error_response(map_exception(exc), request_id_of(request))

        for error_type in KNOWN_ERRORS:
            app.add_exception_handler(error_type, known)

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Runs outside the middleware stack, so it sets the per-response headers itself.
        request_id = request_id_of(request)
        log.error("unexpected failure", exc_info=exc, extra={"request_id": request_id})
        error = ApiError(500, "KEYSTONE_INTERNAL_ERROR", "internal error", False)
        response = error_response(error, request_id)
        response.headers["X-Request-Id"] = request_id
        response.headers["Cache-Control"] = "no-store"
        return response


def _content_type_is(value: str, expected: str) -> bool:
    media, _, params = value.partition(";")
    if media.strip().lower() != expected:
        return False
    for param in filter(None, (p.strip() for p in params.split(";"))):
        name, _, val = param.partition("=")
        if name.strip().lower() != "charset" or val.strip().strip('"').lower() != "utf-8":
            return False
    return True


async def read_body(request: Request, *, content_type: str, max_bytes: int) -> bytes:
    if not _content_type_is(request.headers.get("content-type", ""), content_type):
        raise rejected(415, "VALIDATION_CONTENT_TYPE", f"content type must be {content_type}")
    too_large = rejected(
        413, "VALIDATION_BODY_TOO_LARGE", f"request body exceeds {max_bytes} bytes"
    )
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > max_bytes):
        raise too_large
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > max_bytes:
            raise too_large
    return bytes(body)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _refuse_constant(_: str) -> Any:
    raise ValueError("non-finite number")


def parse_json[M: BaseModel](body: bytes, model: type[M]) -> M:
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise rejected(400, "VALIDATION_ENCODING", "request body must be UTF-8") from exc
    try:
        raw = json.loads(
            text, object_pairs_hook=_no_duplicate_keys, parse_constant=_refuse_constant
        )
    except ValueError as exc:
        raise rejected(400, "VALIDATION_MALFORMED_JSON", "request body is not valid JSON") from exc
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        # Field locations and error kinds only: hostile input is never echoed back.
        problems: list[JsonValue] = [
            {"field": ".".join(str(p) for p in e["loc"]) or "$", "error": e["type"]}
            for e in exc.errors()
        ]
        raise rejected(
            400, "VALIDATION_FAILED", "request failed validation", problems=problems
        ) from exc


async def read_json[M: BaseModel](request: Request, model: type[M], *, max_bytes: int) -> M:
    return parse_json(
        await read_body(request, content_type="application/json", max_bytes=max_bytes), model
    )
