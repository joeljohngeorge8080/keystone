"""`keystone` operator CLI (Ch. 45). Exit codes: 0 ok, 1 finding/divergence, 2 usage error.

`audit verify|export` read PostgreSQL directly (KEYSTONE_DATABASE_URL) or an export file, so the
chain can be checked without trusting the service. Every other command talks to the admin plane
(KEYSTONE_ADMIN_URL + a bearer from KEYSTONE_ADMIN_TOKEN[_FILE]); see `keystone_cli.client`.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import os
import sys
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import IO

from sqlalchemy import create_engine

from keystone.audit.chain import GENESIS_PREV_HASH
from keystone.audit.store import load_events, prev_hash_before, snapshot_head
from keystone.audit.verify import ChainHead, StoredEvent, VerificationResult, verify_chain
from keystone_cli import admin, replay
from keystone_cli.client import AdminClient, ApiFailure, UsageError

DATABASE_URL_ENV = "KEYSTONE_DATABASE_URL"


def _database_url() -> str:
    url = os.environ.get(DATABASE_URL_ENV)
    if not url:
        raise UsageError(f"{DATABASE_URL_ENV} is not set (credentials are never taken from argv)")
    return url


def event_to_json(event: StoredEvent) -> dict[str, object]:
    return {
        "seq": event.seq,
        "id": str(event.id),
        "event_type": event.event_type,
        "occurred_at": event.occurred_at.isoformat(),
        "canonical_payload": base64.b64encode(event.canonical_payload).decode("ascii"),
        "details": event.details,
        "prev_hash": event.prev_hash.hex(),
        "event_hash": event.event_hash.hex(),
    }


def event_from_json(record: dict[str, object]) -> StoredEvent:
    return StoredEvent(
        seq=int(str(record["seq"])),
        id=uuid.UUID(str(record["id"])),
        event_type=str(record["event_type"]),
        occurred_at=datetime.fromisoformat(str(record["occurred_at"])),
        canonical_payload=base64.b64decode(str(record["canonical_payload"])),
        details=record.get("details"),  # type: ignore[arg-type]
        prev_hash=bytes.fromhex(str(record["prev_hash"])),
        event_hash=bytes.fromhex(str(record["event_hash"])),
    )


def _print_result(result: VerificationResult, *, as_json: bool, out: IO[str]) -> None:
    if as_json:
        out.write(json.dumps(dataclasses.asdict(result), default=str) + "\n")
        return
    if result.ok:
        out.write(
            f"OK: {result.events_verified} events verified (last seq {result.last_verified_seq})\n"
        )
    else:
        assert result.finding is not None
        out.write(
            f"DIVERGENCE {result.finding.code} at seq {result.finding.seq}: "
            f"{result.finding.message} ({result.events_verified} events verified before it)\n"
        )


def cmd_audit_export(args: argparse.Namespace, out: IO[str]) -> int:
    engine = create_engine(_database_url())
    with engine.connect() as connection:
        head = snapshot_head(connection)
        hi = head.seq if args.to_seq is None else min(args.to_seq, head.seq)
        header = {"head_seq": head.seq, "head_hash": head.head_hash.hex()}
        out.write(json.dumps({"keystone_audit_export": 1, **header}) + "\n")
        for event in load_events(connection, args.from_seq, hi):
            out.write(json.dumps(event_to_json(event)) + "\n")
    engine.dispose()
    return 0


def _verify_offline(args: argparse.Namespace, out: IO[str]) -> int:
    with open(args.offline, encoding="utf-8") as handle:
        first = handle.readline()
        if not first:
            raise UsageError("empty export file")
        header = json.loads(first)
        if header.get("keystone_audit_export") != 1:
            raise UsageError("not a keystone audit export (missing header line)")
        events = [event_from_json(json.loads(line)) for line in handle if line.strip()]
    if not events:
        raise UsageError("export contains no events")
    start = events[0].seq
    if start != 1:
        raise UsageError("offline verification must start at seq 1 (no trusted prior hash)")
    head = ChainHead(seq=int(header["head_seq"]), head_hash=bytes.fromhex(header["head_hash"]))
    result = verify_chain(
        events, expected_seq=1, expected_prev_hash=GENESIS_PREV_HASH, expected_head=head
    )
    _print_result(result, as_json=args.json, out=out)
    return 0 if result.ok else 1


def cmd_audit_verify(args: argparse.Namespace, out: IO[str]) -> int:
    if args.offline is not None:
        return _verify_offline(args, out)
    engine = create_engine(_database_url())
    with engine.connect() as connection:
        head = snapshot_head(connection)  # pinned before reading (R7)
        lo = args.from_seq
        if lo > head.seq + 1:
            raise UsageError(f"--from {lo} is beyond the chain head (seq {head.seq})")
        hi = head.seq if args.to_seq is None else min(args.to_seq, head.seq)
        prev = prev_hash_before(connection, lo)
        events = load_events(connection, lo, hi)
        expected_head = head if hi == head.seq else None
        result = verify_chain(
            events, expected_seq=lo, expected_prev_hash=prev, expected_head=expected_head
        )
    engine.dispose()
    _print_result(result, as_json=args.json, out=out)
    return 0 if result.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keystone")
    sub = parser.add_subparsers(dest="group", required=True)
    audit = sub.add_parser("audit", help="audit chain operations")
    audit_sub = audit.add_subparsers(dest="command", required=True)

    verify = audit_sub.add_parser("verify", help="recompute and verify the hash chain")
    verify.add_argument(
        "--offline", metavar="EXPORT", help="verify a JSONL export instead of the DB"
    )
    verify.add_argument("--from", dest="from_seq", type=int, default=1)
    verify.add_argument("--to", dest="to_seq", type=int, default=None)
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=cmd_audit_verify)

    export = audit_sub.add_parser("export", help="export events as JSONL for offline verification")
    export.add_argument("--from", dest="from_seq", type=int, default=1)
    export.add_argument("--to", dest="to_seq", type=int, default=None)
    export.set_defaults(func=cmd_audit_export)
    admin.register_audit_tail(audit_sub)

    admin.register(sub)
    replay.register(sub)
    return parser


def main(
    argv: Sequence[str] | None = None,
    out: IO[str] | None = None,
    client_factory: Callable[[], AdminClient] = AdminClient.from_env,
) -> int:
    out = sys.stdout if out is None else out
    args = build_parser().parse_args(argv)
    if getattr(args, "from_seq", 1) < 1:
        sys.stderr.write("--from must be >= 1\n")
        return 2
    try:
        handler: admin.Handler | None = getattr(args, "admin_handler", None)
        code: int = (
            args.func(args, out) if handler is None else handler(args, client_factory(), out)
        )
    except (UsageError, ApiFailure, LookupError, OSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except KeyboardInterrupt:
        return 0  # stopping `tail --follow` is the normal way out
    return code


if __name__ == "__main__":
    raise SystemExit(main())
