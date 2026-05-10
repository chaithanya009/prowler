import json
from datetime import datetime, timedelta, timezone

from django_celery_beat.models import IntervalSchedule, PeriodicTask
from tasks.tasks import perform_scheduled_scan_task, pull_okta_logs_task

from api.db_utils import rls_transaction
from api.exceptions import ConflictException
from api.models import Provider, Scan, StateChoices
from secto.schedules import ensure_log_pull_schedule
from tasks.jobs.attack_paths import db_utils as attack_paths_db_utils


def schedule_provider_scan(provider_instance: Provider):
    tenant_id = str(provider_instance.tenant_id)
    provider_id = str(provider_instance.id)

    if provider_instance.provider == Provider.ProviderChoices.OKTA.value:
        ensure_log_pull_schedule(provider_instance)
        return pull_okta_logs_task.apply_async(
            kwargs={
                "tenant_id": tenant_id,
                "provider_id": provider_id,
            },
            countdown=5,
        )

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=24,
        period=IntervalSchedule.HOURS,
    )

    # Create a unique name for the periodic task
    task_name = f"scan-perform-scheduled-{provider_instance.id}"

    if PeriodicTask.objects.filter(
        interval=schedule, name=task_name, task="scan-perform-scheduled"
    ).exists():
        raise ConflictException(
            detail="There is already a scheduled scan for this provider.",
            pointer="/data/attributes/provider_id",
        )

    with rls_transaction(tenant_id):
        scheduled_scan = Scan.objects.create(
            tenant_id=tenant_id,
            name="Daily scheduled scan",
            provider_id=provider_id,
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.AVAILABLE,
            scheduled_at=datetime.now(timezone.utc),
        )

    attack_paths_db_utils.create_attack_paths_scan(
        tenant_id=tenant_id,
        scan_id=str(scheduled_scan.id),
        provider_id=provider_id,
    )

    # Schedule the task
    periodic_task_instance = PeriodicTask.objects.create(
        interval=schedule,
        name=task_name,
        task="scan-perform-scheduled",
        kwargs=json.dumps(
            {
                "tenant_id": tenant_id,
                "provider_id": provider_id,
            }
        ),
        one_off=False,
        start_time=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    scheduled_scan.scheduler_task_id = periodic_task_instance.id
    scheduled_scan.save()
    ensure_log_pull_schedule(provider_instance)

    return perform_scheduled_scan_task.apply_async(
        kwargs={
            "tenant_id": str(provider_instance.tenant_id),
            "provider_id": provider_id,
        },
        countdown=5,  # Avoid race conditions between the worker and the database
    )
