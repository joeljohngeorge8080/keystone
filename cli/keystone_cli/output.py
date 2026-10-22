"""Tables and JSON for the operator CLI (Ch. 45).

Every value shown in a table passed through a caller-controlled path at some point (repository
names, refs, actors and subjects come from OIDC claims), so control characters are escaped before
they reach the terminal: a hostile claim cannot rewrite the screen or forge a line of output.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import IO, Any

_MAX_CELL = 72
# Line/paragraph separators and bidi embedding/override/isolate controls (Trojan Source).
_INVISIBLE = frozenset({0x2028, 0x2029, *range(0x202A, 0x202F), *range(0x2066, 0x206A)})


def safe(value: object) -> str:
    text = "" if value is None else str(value)
    out = []
    for ch in text:
        code = ord(ch)
        if code < 0x20 or code == 0x7F or 0x80 <= code < 0xA0 or code in _INVISIBLE:
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(ch)
    rendered = "".join(out)
    return rendered if len(rendered) <= _MAX_CELL else rendered[: _MAX_CELL - 1] + "…"


def write_json(out: IO[str], value: Any) -> None:
    # ensure_ascii escapes every control and non-ASCII character, so JSON is terminal-safe too.
    out.write(json.dumps(value, sort_keys=True, ensure_ascii=True) + "\n")


def write_table(out: IO[str], rows: Sequence[Mapping[str, Any]], columns: Sequence[str]) -> None:
    if not rows:
        out.write("(none)\n")
        return
    cells = [[safe(row.get(col)) for col in columns] for row in rows]
    widths = [max(len(col), *(len(r[i]) for r in cells)) for i, col in enumerate(columns)]
    header = "  ".join(col.upper().ljust(w) for col, w in zip(columns, widths, strict=True))
    out.write(header.rstrip() + "\n")
    for row in cells:
        out.write("  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip() + "\n")


def write_stream_row(
    out: IO[str], row: Mapping[str, Any], columns: Sequence[tuple[str, int]], *, header: bool
) -> None:
    """One fixed-width line, for output that streams (tail -f) and cannot size columns."""
    if header:
        out.write("  ".join(name.upper().ljust(width) for name, width in columns).rstrip() + "\n")
    out.write("  ".join(safe(row.get(name)).ljust(width) for name, width in columns).rstrip())
    out.write("\n")


def write_fields(out: IO[str], fields: Mapping[str, Any]) -> None:
    width = max((len(k) for k in fields), default=0)
    for key, value in fields.items():
        shown = json.dumps(value, ensure_ascii=True) if isinstance(value, dict | list) else value
        out.write(f"{key.ljust(width)}  {safe(shown)}\n")
