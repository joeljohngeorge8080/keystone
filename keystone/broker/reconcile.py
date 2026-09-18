"""Startup / periodic issuance reconciler (Ch. 24 as corrected by R6, Ch. 32 R9).

AWS is authoritative for mint facts; the chain is authoritative for integrity. The reconciler
therefore only APPENDS chained events and moves state, in ONE transaction per row, idempotent by
terminal state. CloudTrail is eventually consistent: an absent session is `indeterminate` and
re-checked until the consistency window (default 20 min) has passed, never a premature `failed`.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from pydantic import JsonValue
from sqlalchemy.engine import Engine

from keystone.audit.events import AuditEventInput, EventType
from keystone.audit.sink import AuditSink
from keystone.broker.connectors.base import ACCESS_KEY_PREFIX_LEN
from keystone.broker.issuance import Issuance, IssuanceRepository, IssuanceState

CLOUDTRAIL_CONSISTENCY_WINDOW = timedelta(minutes=20)  # > the ~15 min worst case
UNDELIVERED_GRACE = timedelta(minutes=5)
LOOKUP_BACKSTOP = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class SessionRecord:
    session_name: str
    access_key_prefix: str | None
    minted_at: datetime


class SessionLookup(Protocol):
    def find_session(self, session_name: str, *, not_before: datetime) -> SessionRecord | None: ...


class LookupUnavailable(Exception):
    """CloudTrail/STS could not be queried: the row is left alone and retried next run."""


class Outcome(enum.StrEnum):
    LEFT_INDETERMINATE = "left_indeterminate"
    MARKED_INDETERMINATE = "marked_indeterminate"
    RECONCILED_ISSUED = "reconciled_issued_undelivered"
    RECONCILED_FAILED = "reconciled_failed"
    UNDELIVERED_CLOSED = "undelivered_closed"
    SKIPPED_LOOKUP_ERROR = "skipped_lookup_error"


@dataclass(slots=True)
class ReconcileReport:
    scanned: int = 0
    outcomes: dict[Outcome, int] = field(default_factory=dict)

    def count(self, outcome: Outcome) -> None:
        self.outcomes[outcome] = self.outcomes.get(outcome, 0) + 1


class IssuanceReconciler:
    def __init__(
        self,
        engine: Engine,
        audit: AuditSink,
        lookup: SessionLookup,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        consistency_window: timedelta = CLOUDTRAIL_CONSISTENCY_WINDOW,
        undelivered_grace: timedelta = UNDELIVERED_GRACE,
    ) -> None:
        self._engine = engine
        self._audit = audit
        self._lookup = lookup
        self._clock = clock
        self._window = consistency_window
        self._grace = undelivered_grace

    def run_once(self) -> ReconcileReport:
        report = ReconcileReport()
        with self._engine.connect() as conn:
            pending = IssuanceRepository(conn).non_terminal()
        for issuance in pending:
            report.scanned += 1
            report.count(self._reconcile(issuance))
        return report

    def _reconcile(self, issuance: Issuance) -> Outcome:
        now = self._clock()
        age = now - issuance.created_at
        if issuance.state is IssuanceState.ISSUED:
            if age < self._grace:
                return Outcome.LEFT_INDETERMINATE
            self._close(
                issuance,
                IssuanceState.ISSUED,
                [IssuanceState.DELIVERED],
                EventType.ISSUED_UNDELIVERED,
                {"reason": "delivery_unconfirmed", "access_key_prefix": issuance.access_key_prefix},
            )
            return Outcome.UNDELIVERED_CLOSED

        try:
            session = self._lookup.find_session(
                issuance.session_name, not_before=issuance.created_at - LOOKUP_BACKSTOP
            )
        except LookupUnavailable:
            return Outcome.SKIPPED_LOOKUP_ERROR

        if session is not None:
            # A live session exists that no client received: record it, then terminal.
            self._close(
                issuance,
                issuance.state,
                [IssuanceState.ISSUED, IssuanceState.DELIVERED],
                EventType.ISSUED_UNDELIVERED,
                {
                    "reason": "session_found_by_reconciler",
                    "access_key_prefix": session.access_key_prefix,
                    "minted_at": session.minted_at.astimezone(UTC).isoformat(),
                },
                access_key_prefix=session.access_key_prefix,
                expires_at=session.minted_at + timedelta(seconds=issuance.granted_ttl_seconds),
            )
            return Outcome.RECONCILED_ISSUED

        if age < self._window:
            if issuance.state is IssuanceState.AUTHORIZED:
                self._close(
                    issuance,
                    IssuanceState.AUTHORIZED,
                    [IssuanceState.INDETERMINATE],
                    EventType.STS_INDETERMINATE,
                    {"reason": "no_session_yet_within_consistency_window"},
                )
                return Outcome.MARKED_INDETERMINATE
            return Outcome.LEFT_INDETERMINATE

        # Beyond the window with no session: it was never minted.
        self._close(
            issuance,
            issuance.state,
            [IssuanceState.FAILED],
            EventType.CREDENTIAL_ISSUE_FAILED,
            {
                "reason": "reconciled_no_session_after_window",
                "window_seconds": int(self._window.total_seconds()),
            },
        )
        return Outcome.RECONCILED_FAILED

    def _close(
        self,
        issuance: Issuance,
        from_state: IssuanceState,
        path: list[IssuanceState],
        event_type: EventType,
        data: dict[str, Any],
        *,
        access_key_prefix: str | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        """Audit append + every state transition in ONE transaction (R6 atomicity)."""
        payload: dict[str, JsonValue] = {
            "session_name": issuance.session_name,
            "grant": issuance.grant_name,
            "reconciled": True,
            **{k: v for k, v in data.items() if v is not None},
        }
        with self._engine.begin() as conn:
            repo = IssuanceRepository(conn)
            state = from_state
            for step in path:
                repo.transition(
                    issuance.id,
                    state,
                    step,
                    access_key_prefix=access_key_prefix,
                    expires_at=expires_at,
                )
                state = step
            self._audit.append(
                conn,
                AuditEventInput(
                    event_type=event_type,
                    occurred_at=self._clock(),
                    actor="keystone-reconciler",
                    issuance_id=issuance.id,
                    data=payload,
                ),
            )


class CloudTrailSessionLookup:
    """AssumeRole events joined on RoleSessionName (AMB-4). Read-only; stores no secrets."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def find_session(self, session_name: str, *, not_before: datetime) -> SessionRecord | None:
        import json

        from botocore.exceptions import BotoCoreError, ClientError

        try:
            paginator = self._client.get_paginator("lookup_events")
            pages = paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "AssumeRole"}],
                StartTime=not_before,
            )
            for page in pages:
                for event in page.get("Events", []):
                    detail = json.loads(event.get("CloudTrailEvent", "{}"))
                    params = detail.get("requestParameters") or {}
                    if params.get("roleSessionName") != session_name:
                        continue
                    creds = (detail.get("responseElements") or {}).get("credentials") or {}
                    key_id = creds.get("accessKeyId")
                    minted = event.get("EventTime") or datetime.fromisoformat(detail["eventTime"])
                    return SessionRecord(
                        session_name=session_name,
                        access_key_prefix=str(key_id)[:ACCESS_KEY_PREFIX_LEN] if key_id else None,
                        minted_at=minted if minted.tzinfo else minted.replace(tzinfo=UTC),
                    )
        except (ClientError, BotoCoreError) as exc:
            raise LookupUnavailable(type(exc).__name__) from exc
        return None
