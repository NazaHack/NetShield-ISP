"""Tests for the Celery application and its tenant-isolation guard.

The guard in ``TenantAwareTask`` is the queue-side half of NetShield-ISP's
isolation guarantee, so it is covered directly rather than implicitly.
"""

from __future__ import annotations

import pytest

from app.workers.celery_app import TASK_MODULES, TenantAwareTask, celery_app


@celery_app.task(name="netshield.tests.tenant_guard", base=TenantAwareTask)  # type: ignore[misc]
def _tenant_scoped_task(*, tenant_id: str) -> str:
    """Return the tenant it was invoked for. Exists only for these tests."""
    return tenant_id


def test_task_without_tenant_id_is_refused() -> None:
    """A tenant-scoped task invoked without a tenant must not execute."""
    with pytest.raises(ValueError, match="tenant_id"):
        _tenant_scoped_task()


def test_task_with_empty_tenant_id_is_refused() -> None:
    """An empty tenant identifier is treated the same as a missing one."""
    with pytest.raises(ValueError, match="tenant_id"):
        _tenant_scoped_task(tenant_id="")


def test_task_with_tenant_id_executes() -> None:
    """A correctly scoped invocation reaches the task body."""
    assert _tenant_scoped_task(tenant_id="tenant-abc") == "tenant-abc"


def test_pickle_is_not_an_accepted_serializer() -> None:
    """The broker must refuse pickled payloads in both directions."""
    assert celery_app.conf.accept_content == ["json"]
    assert celery_app.conf.result_accept_content == ["json"]
    assert celery_app.conf.task_serializer == "json"


def test_reliability_settings_suit_long_running_scans() -> None:
    """Late acks and a prefetch of one keep queued scans recoverable."""
    assert celery_app.conf.task_acks_late is True
    assert celery_app.conf.task_reject_on_worker_lost is True
    assert celery_app.conf.worker_prefetch_multiplier == 1


def test_soft_time_limit_precedes_the_hard_limit() -> None:
    """A task must get the chance to clean up before it is killed."""
    assert celery_app.conf.task_soft_time_limit < celery_app.conf.task_time_limit


def test_declared_task_modules_are_importable() -> None:
    """Every module in the explicit registry loads and registers its tasks."""
    celery_app.loader.import_default_modules()
    assert TASK_MODULES
    assert "netshield.system.health_check" in celery_app.tasks
