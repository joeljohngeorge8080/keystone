"""Admin-plane commands (Ch. 45): roles, policy, decisions, audit tail, revoke, tokens.

Each command is one or two admin-route calls; the server enforces every rule (validation,
attribution, audit), so the CLI never re-implements policy. Exit codes: 0 ok, 1 a finding the
operator must act on (pin divergence, a denied or failed decision), 2 usage or API error.
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from collections.abc import Callable, Iterator
from typing import IO, Any

from keystone_cli.client import AdminClient, UsageError
from keystone_cli.output import write_fields, write_json, write_stream_row, write_table

Handler = Callable[[argparse.Namespace, AdminClient, IO[str]], int]
_ROLE_COLUMNS = ("name", "enabled", "max_ttl_seconds", "role_arn", "owner")
_TOKEN_COLUMNS = ("id", "principal", "created_at", "expires_at", "revoked_at")
_PIN_COLUMNS = ("bundle_sequence", "active", "forced_rollback", "pinned_at", "pinned_by", "id")
_EVENT_COLUMNS = ("seq", "event_type", "occurred_at", "actor", "summary")
_STREAM_COLUMNS = (
    ("seq", 8),
    ("event_type", 23),
    ("occurred_at", 27),
    ("actor", 32),
    ("summary", 0),
)
_DECISION_TYPES = frozenset({"decision_allowed", "decision_denied"})
_FAILED_OUTCOMES = frozenset({"credential_issue_failed", "sts_indeterminate"})


def _emit(args: argparse.Namespace, out: IO[str], value: Any, render: Callable[[], None]) -> None:
    if args.json:
        write_json(out, value)
    else:
        render()


# ---------------------------------------------------------------- roles


def roles_list(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    body = client.request("GET", "/v1/roles")
    _emit(args, out, body, lambda: write_table(out, body["roles"], _ROLE_COLUMNS))
    return 0


def roles_get(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    body = client.request("GET", f"/v1/roles/{_name(args.name)}")

    def render() -> None:
        write_fields(out, {k: v for k, v in body.items() if k != "session_policies"})
        out.write("\nsession policies:\n")
        write_table(out, body["session_policies"], ("ref", "enabled"))

    _emit(args, out, body, render)
    return 0


def roles_create(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    payload: dict[str, Any] = {
        "name": args.name,
        "role_arn": args.role_arn,
        "max_ttl_seconds": args.max_ttl,
        "description": args.description,
        "owner": args.owner,
    }
    body = client.request("POST", "/v1/roles", json=payload)
    _emit(args, out, body, lambda: write_fields(out, body))
    return 0


def roles_update(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    patch: dict[str, Any] = {
        "max_ttl_seconds": args.max_ttl,
        "enabled": args.enabled,
        "description": args.description,
        "owner": args.owner,
    }
    patch = {k: v for k, v in patch.items() if v is not None}
    if not patch:
        raise UsageError(
            "nothing to update: pass --max-ttl, --enable/--disable, --description or --owner"
        )
    body = client.request("PATCH", f"/v1/roles/{_name(args.name)}", json=patch)
    _emit(args, out, body, lambda: write_fields(out, body))
    return 0


def roles_add_policy(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    try:
        with open(args.file, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:
        raise UsageError(f"cannot read policy document {args.file}: {exc}") from exc
    if not isinstance(document, dict):
        raise UsageError("the policy document must be a JSON object")
    body = client.request(
        "POST",
        f"/v1/roles/{_name(args.name)}/session-policies",
        json={"ref": args.ref, "policy_document": document},
    )
    _emit(args, out, body, lambda: write_fields(out, body))
    return 0


# ---------------------------------------------------------------- policy


def policy_status(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    body = client.request("GET", "/v1/policy/status")
    pin = body.get("active_pin")

    def render() -> None:
        write_fields(
            out,
            {
                "active_digest": pin["bundle_digest"] if pin else None,
                "active_sequence": pin["bundle_sequence"] if pin else None,
                "loaded_digest": body.get("loaded_digest"),
                "state": "DIVERGENT" if body.get("divergent") else ("ok" if pin else "NO PIN"),
            },
        )

    _emit(args, out, body, render)
    return 1 if pin is None or body.get("divergent") else 0


def policy_pin(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    try:
        with open(args.bundle, "rb") as handle:
            bundle = handle.read()
    except OSError as exc:
        raise UsageError(f"cannot read bundle {args.bundle}: {exc.strerror}") from exc
    body = client.request(
        "POST",
        "/v1/policy/pins",
        params={"force_rollback": "true" if args.force_rollback else None},
        content=bundle,
        content_type="application/gzip",
    )
    _emit(args, out, body, lambda: write_fields(out, body))
    return 0


def policy_history(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    body = client.request("GET", "/v1/policy/pins", params={"limit": args.limit})
    _emit(args, out, body, lambda: write_table(out, body["pins"], _PIN_COLUMNS))
    return 0


# ---------------------------------------------------------------- decisions / audit


def _summary(event: dict[str, Any]) -> str:
    data = event.get("data") or {}
    if not isinstance(data, dict):
        return ""
    parts = []
    for key in ("grant", "repository", "ref", "rule_path", "state", "role", "count"):
        if data.get(key) not in (None, "", []):
            parts.append(f"{key}={data[key]}")
    reasons = data.get("deny_reasons")
    if reasons:
        parts.append("deny=" + ",".join(str(r) for r in reasons))
    return " ".join(parts)


def _event_row(item: dict[str, Any]) -> dict[str, Any]:
    event = item.get("event") or {}
    return {
        "seq": item.get("seq"),
        "event_type": item.get("event_type"),
        "occurred_at": event.get("occurred_at"),
        "actor": event.get("actor"),
        "summary": _summary(event),
    }


def decisions_get(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    body = client.request("GET", f"/v1/decisions/{_uuid(args.decision_id)}")
    events = body["events"]
    _emit(
        args, out, body, lambda: write_table(out, [_event_row(e) for e in events], _EVENT_COLUMNS)
    )
    types = {e.get("event_type") for e in events}
    return 1 if "decision_denied" in types or types & _FAILED_OUTCOMES else 0


def _head_seq(client: AdminClient) -> int:
    # A one-event verification is the cheapest admin read that reports the pinned chain head.
    return int(
        client.request("GET", "/v1/audit/verify", params={"from_seq": 1, "to_seq": 1})["head_seq"]
    )


def _pages(
    client: AdminClient, after_seq: int, event_type: str | None, page_size: int
) -> Iterator[dict[str, Any]]:
    while True:
        body = client.request(
            "GET",
            "/v1/audit/events",
            params={"after_seq": after_seq, "limit": page_size, "event_type": event_type},
        )
        events = body["events"]
        yield from events
        if body.get("next_after_seq") is None or not events:
            return
        after_seq = int(body["next_after_seq"])


def _tail(
    args: argparse.Namespace,
    client: AdminClient,
    out: IO[str],
    *,
    keep: Callable[[dict[str, Any]], bool],
    event_type: str | None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    after = args.after_seq if args.after_seq is not None else max(0, _head_seq(client) - args.last)
    header = True
    polls = 0
    while True:
        for item in _pages(client, after, event_type, page_size=500):
            after = max(after, int(item["seq"]))
            if not keep(item):
                continue
            if args.json:
                write_json(out, item)
            else:
                write_stream_row(out, _event_row(item), _STREAM_COLUMNS, header=header)
                header = False
        out.flush()
        polls += 1
        if not args.follow or (args.max_polls is not None and polls >= args.max_polls):
            return 0
        sleep(args.interval)


def decisions_tail(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    return _tail(
        args, client, out, keep=lambda e: e.get("event_type") in _DECISION_TYPES, event_type=None
    )


def audit_tail(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    return _tail(args, client, out, keep=lambda e: True, event_type=args.event_type)


# ---------------------------------------------------------------- revoke / tokens


def revoke_role(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    payload: dict[str, Any] = {"role": args.name}
    if args.not_before is not None:
        payload["not_before"] = args.not_before
    body = client.request("POST", "/v1/revocations", json=payload)

    def render() -> None:
        write_fields(out, {k: v for k, v in body.items() if k != "rendered_policy"})
        if body.get("rendered_policy") is not None:
            # Mechanism 3 OFF: the operator applies this document by runbook, so print it whole.
            out.write("\ndeny policy to attach to the role (runbook):\n")
            out.write(json.dumps(body["rendered_policy"], indent=2, ensure_ascii=True) + "\n")

    _emit(args, out, body, render)
    return 0


def tokens_list(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    body = client.request("GET", "/v1/admin/tokens")
    _emit(args, out, body, lambda: write_table(out, body["tokens"], _TOKEN_COLUMNS))
    return 0


def tokens_issue(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    body = client.request(
        "POST", "/v1/admin/tokens", json={"principal": args.principal, "ttl_days": args.ttl_days}
    )

    def render() -> None:
        write_fields(out, {k: v for k, v in body.items() if k != "token"})
        # The plaintext exists only in this response; it is shown once and never stored.
        out.write(f"\ntoken (shown once): {body['token']}\n")

    _emit(args, out, body, render)
    return 0


def tokens_revoke(args: argparse.Namespace, client: AdminClient, out: IO[str]) -> int:
    body = client.request("DELETE", f"/v1/admin/tokens/{_uuid(args.token_id)}")
    _emit(args, out, body, lambda: write_fields(out, body))
    return 0


# ---------------------------------------------------------------- parser


def _name(value: str) -> str:
    # Path segments are validated by the server too; refusing '/' here keeps a hostile name
    # from addressing a different route.
    if not value or "/" in value or value in (".", ".."):
        raise UsageError(f"invalid name {value!r}")
    return value


def _uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise UsageError(f"not a UUID: {value!r}") from exc


def _json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def _admin(parser: argparse.ArgumentParser, handler: Handler) -> None:
    _json_flag(parser)
    parser.set_defaults(admin_handler=handler)


def _tail_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--after-seq", type=int, default=None, help="start after this sequence")
    parser.add_argument("--last", type=int, default=20, help="without --after-seq: recent N events")
    parser.add_argument("--follow", "-f", action="store_true", help="keep polling for new events")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between polls")
    parser.add_argument("--max-polls", type=int, default=None, help=argparse.SUPPRESS)


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Add the admin command groups to the top-level parser."""
    roles = sub.add_parser("roles", help="target-role registry").add_subparsers(
        dest="command", required=True
    )
    _admin(roles.add_parser("list", help="list registered roles"), roles_list)
    get = roles.add_parser("get", help="one role and its session policies")
    get.add_argument("name")
    _admin(get, roles_get)
    create = roles.add_parser("create", help="register a role (audited)")
    create.add_argument("name")
    create.add_argument("--role-arn", required=True)
    create.add_argument("--max-ttl", type=int, required=True, help="seconds, 900-3600")
    create.add_argument("--description", default="")
    create.add_argument("--owner", default="")
    _admin(create, roles_create)
    update = roles.add_parser("update", help="patch a role (role ARN is not patchable)")
    update.add_argument("name")
    update.add_argument("--max-ttl", type=int)
    toggle = update.add_mutually_exclusive_group()
    toggle.add_argument("--enable", dest="enabled", action="store_const", const=True)
    toggle.add_argument("--disable", dest="enabled", action="store_const", const=False)
    update.add_argument("--description")
    update.add_argument("--owner")
    _admin(update, roles_update)
    add_policy = roles.add_parser("add-policy", help="approve a session-policy template")
    add_policy.add_argument("name")
    add_policy.add_argument("--ref", required=True)
    add_policy.add_argument("--file", required=True, help="IAM policy document (JSON)")
    _admin(add_policy, roles_add_policy)

    policy = sub.add_parser("policy", help="policy pins (R5/R8)").add_subparsers(
        dest="command", required=True
    )
    _admin(policy.add_parser("status", help="active pin vs OPA's loaded bundle"), policy_status)
    pin = policy.add_parser("pin", help="activate a CI-signed bundle (two-phase)")
    pin.add_argument("bundle", help="signed bundle .tar.gz")
    pin.add_argument("--force-rollback", action="store_true", help="pin a lower sequence (audited)")
    _admin(pin, policy_pin)
    history = policy.add_parser("history", help="pin history, newest first")
    history.add_argument("--limit", type=int, default=50)
    _admin(history, policy_history)

    decisions = sub.add_parser("decisions", help="authorization decisions").add_subparsers(
        dest="command", required=True
    )
    dget = decisions.add_parser("get", help="a decision and its issuance outcome")
    dget.add_argument("decision_id")
    _admin(dget, decisions_get)
    dtail = decisions.add_parser("tail", help="recent decisions")
    _tail_flags(dtail)
    _admin(dtail, decisions_tail)

    revoke = sub.add_parser("revoke", help="revocation (Ch. 26)").add_subparsers(
        dest="command", required=True
    )
    rrole = revoke.add_parser("role", help="revoke every live session of a role")
    rrole.add_argument("name")
    rrole.add_argument("--not-before", help="RFC 3339 cut-off; default now, never in the future")
    _admin(rrole, revoke_role)

    tokens = sub.add_parser("tokens", help="admin bearer tokens").add_subparsers(
        dest="command", required=True
    )
    _admin(
        tokens.add_parser("list", help="list tokens (hashes never leave the server)"), tokens_list
    )
    issue = tokens.add_parser("issue", help="issue a token; the plaintext is shown once")
    issue.add_argument("--principal", required=True)
    issue.add_argument("--ttl-days", type=int, default=30, help="1-90")
    _admin(issue, tokens_issue)
    trevoke = tokens.add_parser("revoke", help="revoke a token")
    trevoke.add_argument("token_id")
    _admin(trevoke, tokens_revoke)


def register_audit_tail(audit_sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    tail = audit_sub.add_parser("tail", help="recent audit events from the admin plane")
    tail.add_argument("--type", dest="event_type", help="only this event type")
    _tail_flags(tail)
    _admin(tail, audit_tail)
