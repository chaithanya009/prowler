import json
from unittest.mock import patch

import pytest
from django_celery_beat.models import IntervalSchedule, PeriodicTask
from tasks.beat import schedule_provider_scan

from api.exceptions import ConflictException
from api.models import Provider, Scan


@pytest.mark.django_db
class TestScheduleProviderScan:
    def test_schedule_provider_scan_success(self, providers_fixture):
        provider_instance, *_ = providers_fixture

        with patch(
            "tasks.tasks.perform_scheduled_scan_task.apply_async"
        ) as mock_apply_async:
            assert Scan.all_objects.count() == 0
            result = schedule_provider_scan(provider_instance)

            assert result is not None
            assert Scan.all_objects.count() == 1

            mock_apply_async.assert_called_once_with(
                kwargs={
                    "tenant_id": str(provider_instance.tenant_id),
                    "provider_id": str(provider_instance.id),
                },
                countdown=5,
            )

            task_name = f"scan-perform-scheduled-{provider_instance.id}"
            periodic_task = PeriodicTask.objects.get(name=task_name)
            assert periodic_task is not None
            assert periodic_task.interval.every == 24
            assert periodic_task.interval.period == IntervalSchedule.HOURS
            assert periodic_task.task == "scan-perform-scheduled"
            assert json.loads(periodic_task.kwargs) == {
                "tenant_id": str(provider_instance.tenant_id),
                "provider_id": str(provider_instance.id),
            }

    def test_schedule_provider_scan_already_exists(self, providers_fixture):
        provider_instance, *_ = providers_fixture

        # First, schedule the scan
        with patch("tasks.tasks.perform_scheduled_scan_task.apply_async"):
            schedule_provider_scan(provider_instance)

        # Now, try scheduling again, should raise ConflictException
        with pytest.raises(ConflictException) as exc_info:
            schedule_provider_scan(provider_instance)

        assert "There is already a scheduled scan for this provider." in str(
            exc_info.value
        )

    def test_schedule_okta_provider_starts_only_log_pull(self, tenants_fixture):
        tenant = tenants_fixture[0]
        provider_instance = Provider.objects.create(
            tenant_id=tenant.id,
            provider=Provider.ProviderChoices.OKTA,
            uid="acme.okta.com",
            alias="okta",
        )

        with patch("tasks.tasks.pull_okta_logs_task.apply_async") as mock_apply_async:
            assert Scan.all_objects.count() == 0
            result = schedule_provider_scan(provider_instance)

            assert result is not None
            assert Scan.all_objects.count() == 0
            mock_apply_async.assert_called_once_with(
                kwargs={
                    "tenant_id": str(provider_instance.tenant_id),
                    "provider_id": str(provider_instance.id),
                },
                countdown=5,
            )

            log_pull_task = PeriodicTask.objects.get(
                name=f"secto-okta-log-pull-{provider_instance.id}"
            )
            assert log_pull_task.interval.every == 5
            assert log_pull_task.interval.period == IntervalSchedule.MINUTES
            assert log_pull_task.task == "secto-okta-log-pull"

    def test_remove_periodic_task(self, providers_fixture):
        provider_instance = providers_fixture[0]

        assert Scan.objects.count() == 0
        with patch("tasks.tasks.perform_scheduled_scan_task.apply_async"):
            schedule_provider_scan(provider_instance)

        assert Scan.objects.count() == 1
        scan = Scan.objects.first()
        periodic_task = scan.scheduler_task
        assert periodic_task is not None

        periodic_task.delete()

        scan.refresh_from_db()
        # Assert the scan still exists but its scheduler_task is set to None
        # Otherwise, Scan.DoesNotExist would be raised
        assert Scan.objects.get(id=scan.id).scheduler_task is None
