"""Celery topology (Ch. 9 as amended by R7): two workers, two queues, never shared.

`keystone-worker` runs aggregation flushes, retention, JWKS prefetch and the reconcilers.
`keystone-anchor` runs ONLY anchoring and scheduled chain verification, so a flood of
aggregation work can never starve the tamper-evidence checkpoint.
"""

from __future__ import annotations

from celery import Celery

GENERAL_QUEUE = "keystone-worker"
ANCHOR_QUEUE = "keystone-anchor"

TASK_ROUTES: dict[str, dict[str, str]] = {
    "keystone.workers.tasks.flush_aggregation": {"queue": GENERAL_QUEUE},
    "keystone.workers.tasks.prefetch_jwks": {"queue": GENERAL_QUEUE},
    "keystone.workers.tasks.reconcile_issuances": {"queue": GENERAL_QUEUE},
    "keystone.workers.tasks.reconcile_revocations": {"queue": GENERAL_QUEUE},
    "keystone.workers.tasks.ensure_partitions": {"queue": GENERAL_QUEUE},
    "keystone.workers.tasks.anchor_chain": {"queue": ANCHOR_QUEUE},
    "keystone.workers.tasks.verify_chain": {"queue": ANCHOR_QUEUE},
}

BEAT_SCHEDULE: dict[str, dict[str, object]] = {
    "flush-aggregation": {"task": "keystone.workers.tasks.flush_aggregation", "schedule": 60.0},
    "prefetch-jwks": {"task": "keystone.workers.tasks.prefetch_jwks", "schedule": 300.0},
    "reconcile-issuances": {
        "task": "keystone.workers.tasks.reconcile_issuances",
        "schedule": 300.0,
    },
    "reconcile-revocations": {
        "task": "keystone.workers.tasks.reconcile_revocations",
        "schedule": 300.0,
    },
    "ensure-partitions": {"task": "keystone.workers.tasks.ensure_partitions", "schedule": 86400.0},
    "anchor-chain": {"task": "keystone.workers.tasks.anchor_chain", "schedule": 60.0},
    "verify-chain": {"task": "keystone.workers.tasks.verify_chain", "schedule": 300.0},
}


def make_celery(broker_url: str) -> Celery:
    app = Celery("keystone", broker=broker_url)
    app.conf.update(
        task_routes=TASK_ROUTES,
        beat_schedule=BEAT_SCHEDULE,
        task_default_queue=GENERAL_QUEUE,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_serializer="json",
        accept_content=["json"],
        result_backend=None,
        task_ignore_result=True,
        broker_connection_retry_on_startup=True,
        timezone="UTC",
    )
    return app


def queue_for(task_name: str) -> str:
    return TASK_ROUTES[task_name]["queue"]
