import json
from datetime import datetime, timezone

from django_celery_beat.models import IntervalSchedule, PeriodicTask

from api.db_utils import rls_transaction
from api.models import Provider

LOG_PULL_TASKS = {
    Provider.ProviderChoices.M365.value: "secto-m365-log-pull",
    Provider.ProviderChoices.OKTA.value: "secto-okta-log-pull",
}


def ensure_log_pull_schedule(provider: Provider) -> PeriodicTask | None:
    task_name = LOG_PULL_TASKS.get(provider.provider)
    if task_name is None:
        return None

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=5,
        period=IntervalSchedule.MINUTES,
    )
    task, _ = PeriodicTask.objects.update_or_create(
        name=f"{task_name}-{provider.id}",
        defaults={
            "interval": schedule,
            "task": task_name,
            "kwargs": json.dumps(
                {
                    "tenant_id": str(provider.tenant_id),
                    "provider_id": str(provider.id),
                }
            ),
            "enabled": True,
            "start_time": datetime.now(timezone.utc),
        },
    )
    return task


def ensure_log_pull_schedule_for_provider(
    tenant_id: str,
    provider_id: str,
) -> PeriodicTask | None:
    with rls_transaction(tenant_id):
        provider = Provider.objects.get(tenant_id=tenant_id, id=provider_id)
    return ensure_log_pull_schedule(provider)
