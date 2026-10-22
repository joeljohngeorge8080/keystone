"""Clock-sync signal (Ch. 31): is the host clock NTP-disciplined within the 30 s desync budget?

Read-only `adjtimex(2)` (modes = 0 needs no privilege and works inside containers, which share
the host kernel's clock state). TIME_ERROR means the kernel considers the clock unsynchronised;
otherwise `maxerror` bounds the offset. Non-Linux hosts report `unknown`.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import sys
from collections.abc import Callable

SYNCED = "ok"
UNSYNCED = "unsynced"
DESYNCED = "desynced"
UNKNOWN = "unknown"
MAX_DESYNC_MICROSECONDS = 30_000_000  # Ch. 31: readiness degrades on desync > 30 s
_TIME_ERROR = 5


class _Timeval(ctypes.Structure):
    _fields_ = (("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long))


class _Timex(ctypes.Structure):
    # glibc `struct timex`; ctypes applies the same natural alignment as the C compiler.
    _fields_ = (
        ("modes", ctypes.c_uint),
        ("offset", ctypes.c_long),
        ("freq", ctypes.c_long),
        ("maxerror", ctypes.c_long),
        ("esterror", ctypes.c_long),
        ("status", ctypes.c_int),
        ("constant", ctypes.c_long),
        ("precision", ctypes.c_long),
        ("tolerance", ctypes.c_long),
        ("time", _Timeval),
        ("tick", ctypes.c_long),
        ("ppsfreq", ctypes.c_long),
        ("jitter", ctypes.c_long),
        ("shift", ctypes.c_int),
        ("stabil", ctypes.c_long),
        ("jitcnt", ctypes.c_long),
        ("calcnt", ctypes.c_long),
        ("errcnt", ctypes.c_long),
        ("stbcnt", ctypes.c_long),
        ("tai", ctypes.c_int),
        ("_reserved", ctypes.c_int * 11),
    )


def kernel_clock_state() -> tuple[int, int] | None:
    """(adjtimex return code, maxerror in microseconds), or None when unavailable."""
    if not sys.platform.startswith("linux"):
        return None
    name = ctypes.util.find_library("c")
    if name is None:
        return None
    libc = ctypes.CDLL(name, use_errno=True)
    timex = _Timex()  # modes = 0: read only
    code = int(libc.adjtimex(ctypes.byref(timex)))
    if code < 0:
        return None
    return code, int(timex.maxerror)


def clock_sync_state(read: Callable[[], tuple[int, int] | None] = kernel_clock_state) -> str:
    try:
        state = read()
    except OSError:
        return UNKNOWN
    if state is None:
        return UNKNOWN
    code, maxerror_us = state
    if code == _TIME_ERROR:
        return UNSYNCED
    return DESYNCED if maxerror_us > MAX_DESYNC_MICROSECONDS else SYNCED
