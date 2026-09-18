"""Celery task bodies: thin wrappers that build the runtime from Settings and call components."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache

import boto3
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from keystone.audit.aggregation import FailureAggregator
from keystone.audit.anchor import (
    AnchorBreaker,
    Anchorer,
    AnchorSigner,
    S3ObjectLockAnchorStore,
)
from keystone.audit.sink import PostgresAuditSink
from keystone.audit.verification import ChainVerificationTask
from keystone.broker.reconcile import CloudTrailSessionLookup, IssuanceReconciler
from keystone.broker.revocation import IamDenyPolicyApplier, RevocationService
from keystone.config.settings import Settings
from keystone.db.partitions import ensure_audit_partition, month_starts
from keystone.db.redis import make_redis
from keystone.identity.jwks import HttpJwksSource, JwksCache
from keystone.workers.celery_app import make_celery

app = make_celery(os.environ.get("KEYSTONE_CELERY_BROKER_URL", "memory://"))


@dataclass(slots=True)
class Runtime:
    settings: Settings
    engine: Engine

    def audit(self) -> PostgresAuditSink:
        return PostgresAuditSink()


@lru_cache(maxsize=1)
def runtime() -> Runtime:
    settings = Settings.from_env(os.environ)
    return Runtime(
        settings=settings, engine=create_engine(settings.database_url, pool_pre_ping=True)
    )


def _anchor_signer(settings: Settings) -> AnchorSigner:
    if not settings.anchor_key_pem_path:
        raise RuntimeError("KEYSTONE_ANCHOR_KEY_PEM_PATH is required for the anchor worker (A8)")
    with open(settings.anchor_key_pem_path, "rb") as handle:
        return AnchorSigner.from_pem(handle.read())


@app.task(name="keystone.workers.tasks.flush_aggregation")
def flush_aggregation() -> int:
    rt = runtime()
    aggregator = FailureAggregator(make_redis(rt.settings.effective_aggregation_redis_url))
    with rt.engine.begin() as conn:
        return sum(b.rows_written for b in aggregator.flush(conn, rt.audit()))


@app.task(name="keystone.workers.tasks.prefetch_jwks")
def prefetch_jwks() -> None:
    rt = runtime()
    JwksCache(make_redis(rt.settings.redis_url), HttpJwksSource(rt.settings.jwks_url)).prefetch()


@app.task(name="keystone.workers.tasks.reconcile_issuances")
def reconcile_issuances() -> dict[str, int]:
    rt = runtime()
    lookup = CloudTrailSessionLookup(boto3.client("cloudtrail", region_name=rt.settings.aws_region))
    report = IssuanceReconciler(rt.engine, rt.audit(), lookup).run_once()
    return {k.value: v for k, v in report.outcomes.items()}


@app.task(name="keystone.workers.tasks.reconcile_revocations")
def reconcile_revocations() -> int:
    rt = runtime()
    applier = IamDenyPolicyApplier(
        boto3.client("iam", region_name=rt.settings.aws_region),
        enabled=rt.settings.revocation_put_role_policy_enabled,
    )
    return RevocationService(rt.engine, rt.audit(), applier).reconcile_open()


@app.task(name="keystone.workers.tasks.ensure_partitions")
def ensure_partitions(months_ahead: int = 14) -> int:
    rt = runtime()
    with rt.engine.begin() as conn:
        created = 0
        for month in month_starts(date.today(), count=months_ahead):
            ensure_audit_partition(conn, month)
            created += 1
    return created


@app.task(name="keystone.workers.tasks.anchor_chain")
def anchor_chain() -> dict[str, object]:
    rt = runtime()
    if not rt.settings.anchor_bucket:
        raise RuntimeError("KEYSTONE_ANCHOR_BUCKET is required for the anchor worker")
    store = S3ObjectLockAnchorStore(
        boto3.client("s3", region_name=rt.settings.aws_region), bucket=rt.settings.anchor_bucket
    )
    breaker = AnchorBreaker(
        make_redis(rt.settings.redis_url),
        threshold=timedelta(seconds=rt.settings.anchor_breaker_threshold_seconds),
    )
    outcome = Anchorer(
        rt.engine, rt.audit(), _anchor_signer(rt.settings), store, breaker
    ).anchor_once()
    return {"anchored": outcome.anchored, "chain_seq": outcome.chain_seq, "reason": outcome.reason}


@app.task(name="keystone.workers.tasks.verify_chain")
def verify_chain() -> dict[str, int]:
    rt = runtime()
    result = ChainVerificationTask(rt.engine, _anchor_signer(rt.settings).public_key()).run_once()
    return {
        "from_seq": result.from_seq,
        "to_seq": result.to_seq,
        "events_verified": result.events_verified,
        "anchors_verified": result.anchors_verified,
    }


def now_utc() -> datetime:
    return datetime.now(UTC)
