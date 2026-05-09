import json
from datetime import datetime, timezone

from django_celery_beat.models import IntervalSchedule, PeriodicTask

from api.db_utils import rls_transaction
from api.models import Provider


def ensure_m365_log_pull_schedule(provider: Provider) -> PeriodicTask | None:
    if provider.provider != Provider.ProviderChoices.M365.value:
        return None

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=5,
        period=IntervalSchedule.MINUTES,
    )
    task, _ = PeriodicTask.objects.update_or_create(
        name=f"secto-m365-log-pull-{provider.id}",
        defaults={
            "interval": schedule,
            "task": "secto-m365-log-pull",
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


def ensure_m365_log_pull_schedule_for_provider(
    tenant_id: str,
    provider_id: str,
) -> PeriodicTask | None:
    with rls_transaction(tenant_id):
        provider = Provider.objects.get(tenant_id=tenant_id, id=provider_id)
    return ensure_m365_log_pull_schedule(provider)
