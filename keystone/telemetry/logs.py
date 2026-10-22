"""Structured JSON-line logging (Ch. 49): operational telemetry, never the audit record.

One object per line on stderr with `ts`, `level`, `plane`, `component`, `message`, and the
`request_id` / `decision_id` of the request being served (from context variables the HTTP
middleware sets, so log calls deep in a stage need not thread them through). The serializer
denylist redacts any field whose name looks like a token, secret, key, password or
authorization header, at any nesting depth, before anything is written.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
import traceback
from datetime import UTC, datetime
from typing import Any

REDACTED = "[redacted]"
_DENY = re.compile(r"token|secret|password|passwd|authorization|cookie|private|(^|_)key$", re.I)
# Attributes every LogRecord carries; anything else on the record came from `extra=`.
_STANDARD = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message",
    "asctime",
    "taskName",
    "color_message",  # uvicorn's ANSI-coloured duplicate of `message`
}

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "keystone_request_id", default=None
)
decision_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "keystone_decision_id", default=None
)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): REDACTED if _DENY.search(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    if value is None or isinstance(value, bool | int | float | str):
        return value
    return str(value)


class JsonFormatter(logging.Formatter):
    def __init__(self, plane: str) -> None:
        super().__init__()
        self._plane = plane

    def format(self, record: logging.LogRecord) -> str:
        body: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "plane": self._plane,
            "component": record.name,
            "message": record.getMessage(),
        }
        request_id = request_id_var.get()
        decision_id = decision_id_var.get()
        if request_id is not None:
            body["request_id"] = request_id
        if decision_id is not None:
            body["decision_id"] = decision_id
        extra = {k: v for k, v in vars(record).items() if k not in _STANDARD}
        if extra:
            body.update(redact(extra))
        if record.exc_info and record.exc_info[0] is not None:
            # Type and frame locations only: exception messages can carry bound SQL
            # parameters, addresses or request input, so their text is never logged.
            body["exception"] = record.exc_info[0].__name__
            body["frames"] = [
                f"{frame.filename}:{frame.lineno} {frame.name}"
                for frame in traceback.extract_tb(record.exc_info[2])
            ]
        return json.dumps(body, separators=(",", ":"), default=str)


def configure_logging(plane: str, level: str = "INFO") -> None:
    """Route the root logger and uvicorn's loggers through one JSON handler on stderr."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter(plane))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "celery"):
        logger = logging.getLogger(name)
        logger.handlers[:] = []
        logger.propagate = True
