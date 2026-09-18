"""Worker topology (R7): anchoring and verification are isolated from general-queue load."""

from keystone.workers.celery_app import (
    ANCHOR_QUEUE,
    BEAT_SCHEDULE,
    GENERAL_QUEUE,
    TASK_ROUTES,
    make_celery,
    queue_for,
)


def test_anchor_and_verify_run_on_the_dedicated_queue() -> None:
    assert queue_for("keystone.workers.tasks.anchor_chain") == ANCHOR_QUEUE
    assert queue_for("keystone.workers.tasks.verify_chain") == ANCHOR_QUEUE
    general = {name for name, route in TASK_ROUTES.items() if route["queue"] == GENERAL_QUEUE}
    assert "keystone.workers.tasks.flush_aggregation" in general
    assert "keystone.workers.tasks.reconcile_issuances" in general
    assert ANCHOR_QUEUE != GENERAL_QUEUE


def test_every_scheduled_task_has_a_route_and_sane_cadence() -> None:
    for name, entry in BEAT_SCHEDULE.items():
        assert entry["task"] in TASK_ROUTES, name
    assert BEAT_SCHEDULE["anchor-chain"]["schedule"] == 60.0  # Ch. 32 default anchoring cadence
    assert BEAT_SCHEDULE["verify-chain"]["schedule"] == 300.0  # F9/R7 default verification cadence


def test_celery_config_is_at_least_once_and_json_only() -> None:
    app = make_celery("memory://")
    assert app.conf.task_acks_late is True
    assert app.conf.task_reject_on_worker_lost is True
    assert app.conf.accept_content == ["json"]
    assert app.conf.task_default_queue == GENERAL_QUEUE
    assert app.conf.task_routes == TASK_ROUTES


def test_tasks_module_imports_without_environment() -> None:
    from keystone.workers import tasks

    assert tasks.app.conf.task_routes == TASK_ROUTES
    assert tasks.anchor_chain.name == "keystone.workers.tasks.anchor_chain"
