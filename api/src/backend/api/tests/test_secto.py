import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest
import requests
from django_celery_beat.models import IntervalSchedule, PeriodicTask
from tasks.beat import schedule_provider_scan
from tasks.tasks import perform_scan_task

from api.models import Provider, ProviderSecret, Scan, StateChoices
from api.v1.serializers import BaseWriteProviderSecretSerializer
from secto.ingestion import pull_m365_logs, pull_okta_logs
from secto.models import (
    M365AuditLog,
    M365SignInLog,
    M365UnifiedAuditLog,
    OktaSystemLog,
    SectoLogCursor,
    SectoThreat,
)
from secto.rules.runner import run_rules_for_provider
from secto.schedules import ensure_log_pull_schedule

OFFICE_HOME_APP_ID = "4765445b-32c6-49b0-83e6-1d93765276ca"


@pytest.mark.django_db
class TestSectoSessionHijacking:
    def test_detects_office_home_session_reused_from_another_country(
        self, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[5]
        now = datetime.now(timezone.utc).replace(microsecond=0)

        M365SignInLog.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            source_id="office-home",
            timestamp=now - timedelta(minutes=10),
            app_id=OFFICE_HOME_APP_ID,
            app_display_name="OfficeHome",
            client_app_used="Browser",
            is_interactive=True,
            session_id="session-1",
            status={"errorCode": "0"},
            location={"countryOrRegion": "US"},
            ip_address="198.51.100.10",
            user_id="user-1",
            user_display_name="User One",
            user_principal_name="user@example.com",
            raw_event={"id": "office-home"},
        )
        M365SignInLog.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            source_id="sharepoint",
            timestamp=now - timedelta(minutes=5),
            app_id="00000003-0000-0ff1-ce00-000000000000",
            app_display_name="SharePoint Online",
            client_app_used="Browser",
            is_interactive=True,
            session_id="session-1",
            status={"errorCode": "0"},
            location={"countryOrRegion": "CN"},
            ip_address="203.0.113.20",
            user_id="user-1",
            user_display_name="User One",
            user_principal_name="user@example.com",
            raw_event={"id": "sharepoint"},
        )

        threats = run_rules_for_provider(
            tenant_id=str(tenant.id),
            provider_id=str(provider.id),
            provider_type=Provider.ProviderChoices.M365.value,
        )

        assert len(threats) == 1
        threat = threats[0]
        assert threat.rule_id == "signin_session_cookie_hijacking"
        assert threat.alert_key == "session-1"
        assert threat.dedup_window_start == datetime.fromtimestamp(
            int((now - timedelta(minutes=10)).timestamp()) // 86400 * 86400,
            tz=timezone.utc,
        )
        assert threat.severity == SectoThreat.SeverityChoices.CRITICAL
        assert threat.affected_users == ["user@example.com"]
        assert threat.source_ip_addresses == ["203.0.113.20"]
        assert threat.countries == ["CN"]
        assert threat.evidence["applications"] == ["SharePoint Online"]
        assert threat.first_seen == now - timedelta(minutes=10)
        assert threat.last_seen == now - timedelta(minutes=5)

        run_rules_for_provider(
            tenant_id=str(tenant.id),
            provider_id=str(provider.id),
            provider_type=Provider.ProviderChoices.M365.value,
        )
        assert SectoThreat.objects.count() == 1

    def test_ignores_same_country_session_activity(
        self, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[5]
        now = datetime.now(timezone.utc).replace(microsecond=0)

        for source_id, app_id, minutes in (
            ("office-home", OFFICE_HOME_APP_ID, 10),
            ("teams", "1fec8e78-bce4-4aaf-ab1b-5451cc387264", 5),
        ):
            M365SignInLog.objects.create(
                tenant_id=tenant.id,
                provider=provider,
                source_id=source_id,
                timestamp=now - timedelta(minutes=minutes),
                app_id=app_id,
                app_display_name=source_id,
                client_app_used="Browser",
                is_interactive=True,
                session_id="session-2",
                status={"errorCode": "0"},
                location={"countryOrRegion": "US"},
                ip_address="198.51.100.10",
                user_principal_name="user@example.com",
                raw_event={"id": source_id},
            )

        threats = run_rules_for_provider(
            tenant_id=str(tenant.id),
            provider_id=str(provider.id),
            provider_type=Provider.ProviderChoices.M365.value,
        )

        assert threats == []
        assert SectoThreat.objects.count() == 0


@pytest.mark.django_db
class TestSectoIngestion:
    def test_pull_okta_logs_stores_system_logs_and_updates_cursor(
        self, tenants_fixture
    ):
        tenant = tenants_fixture[0]
        provider = Provider.objects.create(
            tenant_id=tenant.id,
            provider=Provider.ProviderChoices.OKTA,
            uid="acme.okta.com",
            alias="okta",
        )
        ProviderSecret.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            secret_type=ProviderSecret.TypeChoices.STATIC,
            name="okta",
            secret={"api_token": "fake-api-token"},
        )
        now = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        first_body = [
            {
                "uuid": "event-1",
                "published": "2026-05-09T11:50:00.000Z",
                "eventType": "user.session.start",
                "displayMessage": "User login to Okta",
                "severity": "INFO",
                "outcome": {"result": "SUCCESS"},
                "actor": {
                    "id": "user-1",
                    "alternateId": "user@example.com",
                    "displayName": "User One",
                },
                "client": {
                    "ipAddress": "198.51.100.10",
                    "userAgent": {"rawUserAgent": "Mozilla/5.0"},
                },
                "request": {
                    "ipChain": [
                        {
                            "ip": "198.51.100.10",
                            "geographicalContext": {"country": "United States"},
                        }
                    ]
                },
                "target": [{"id": "app-1", "type": "AppInstance"}],
            }
        ]
        second_body = [
            {
                "uuid": "event-2",
                "published": "2026-05-09T11:55:00.000Z",
                "eventType": "user.mfa.factor.activate",
                "displayMessage": "Activate factor",
                "severity": "WARN",
            }
        ]

        def response(body, links=None):
            mocked_response = Mock()
            mocked_response.json.return_value = body
            mocked_response.raise_for_status.return_value = None
            mocked_response.links = links or {}
            return mocked_response

        def get_response(url, params=None, **kwargs):
            assert kwargs["headers"]["Authorization"] == "SSWS fake-api-token"
            if params:
                assert url == "https://acme.okta.com/api/v1/logs"
                assert params["sortOrder"] == "ASCENDING"
                assert params["limit"] == 1000
                assert params["since"] == "2026-05-08T12:00:00Z"
                assert params["until"] == "2026-05-09T12:00:00Z"
                return response(
                    first_body,
                    {"next": {"url": "https://acme.okta.com/api/v1/logs?after=abc"}},
                )
            assert url == "https://acme.okta.com/api/v1/logs?after=abc"
            return response(second_body)

        with patch("secto.ingestion.requests.get", side_effect=get_response):
            result = pull_okta_logs(
                tenant_id=str(tenant.id),
                provider_id=str(provider.id),
                now=now,
            )

        assert result == {"system_events": 2}
        assert OktaSystemLog.objects.count() == 2
        assert OktaSystemLog.objects.get(source_id="event-1").actor_alternate_id == (
            "user@example.com"
        )
        cursor = SectoLogCursor.objects.get(provider=provider)
        assert cursor.okta_system_cursor_at == now

    def test_validate_okta_secret_requires_api_token(self):
        BaseWriteProviderSecretSerializer.validate_secret_based_on_provider(
            Provider.ProviderChoices.OKTA.value,
            ProviderSecret.TypeChoices.STATIC,
            {"api_token": "fake-api-token"},
        )

    def test_pull_m365_logs_stores_events_updates_cursor_and_detects_threat(
        self, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[5]
        ProviderSecret.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            secret_type=ProviderSecret.TypeChoices.STATIC,
            name="m365",
            secret={
                "tenant_id": "00000000-0000-4000-8000-000000000000",
                "client_id": "11111111-1111-4111-8111-111111111111",
                "client_secret": "fake-client-secret",
            },
        )

        now = datetime.now(timezone.utc).replace(microsecond=0)
        signin_body = {
            "value": [
                {
                    "id": "office-home",
                    "createdDateTime": (now - timedelta(minutes=10))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "appId": OFFICE_HOME_APP_ID,
                    "appDisplayName": "OfficeHome",
                    "clientAppUsed": "Browser",
                    "isInteractive": True,
                    "sessionId": "session-3",
                    "status": {"errorCode": 0},
                    "location": {"countryOrRegion": "US"},
                    "ipAddress": "198.51.100.10",
                    "userId": "user-1",
                    "userDisplayName": "User One",
                    "userPrincipalName": "user@example.com",
                },
                {
                    "id": "sharepoint",
                    "createdDateTime": (now - timedelta(minutes=5))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "appId": "00000003-0000-0ff1-ce00-000000000000",
                    "appDisplayName": "SharePoint Online",
                    "clientAppUsed": "Browser",
                    "isInteractive": True,
                    "sessionId": "session-3",
                    "status": {"errorCode": "0"},
                    "location": {"countryOrRegion": "CN"},
                    "ipAddress": "203.0.113.20",
                    "userId": "user-1",
                    "userDisplayName": "User One",
                    "userPrincipalName": "user@example.com",
                },
            ]
        }
        audit_body = {
            "value": [
                {
                    "id": "audit-1",
                    "activityDateTime": (now - timedelta(minutes=4))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "activityDisplayName": "Update user",
                    "category": "UserManagement",
                    "operationType": "Update",
                    "result": "success",
                    "initiatedBy": {"user": {"userPrincipalName": "admin@example.com"}},
                    "targetResources": [{"displayName": "User One"}],
                }
            ]
        }
        unified_audit_record = {
            "Id": "unified-1",
            "CreationTime": (now - timedelta(minutes=3))
            .isoformat()
            .replace("+00:00", "Z"),
            "RecordType": 8,
            "Operation": "FileAccessed",
            "Workload": "SharePoint",
            "UserId": "user@example.com",
            "UserPrincipalName": "user@example.com",
            "ClientIP": "203.0.113.20",
            "ObjectId": "https://contoso.sharepoint.com/doc",
        }

        fake_credential = Mock()
        fake_credential.get_token.return_value.token = "fake-token"

        def response(body):
            mocked_response = Mock()
            mocked_response.json.return_value = body
            mocked_response.raise_for_status.return_value = None
            return mocked_response

        def get_response(url, params=None, **kwargs):
            if url.endswith("/auditLogs/signIns"):
                return response(signin_body)
            if url.endswith("/auditLogs/directoryAudits"):
                return response(audit_body)
            if url.endswith("/subscriptions/list"):
                return response([{"contentType": params["contentType"]}])
            if url.endswith("/subscriptions/content"):
                if params["contentType"] == "Audit.AzureActiveDirectory":
                    return response([{"contentUri": "https://content.example/audit"}])
                return response([])
            if url == "https://content.example/audit":
                return response([unified_audit_record])
            raise AssertionError(f"Unexpected URL: {url}")

        with (
            patch(
                "secto.ingestion.ClientSecretCredential",
                return_value=fake_credential,
            ),
            patch("secto.ingestion.requests.get", side_effect=get_response),
        ):
            result = pull_m365_logs(
                tenant_id=str(tenant.id), provider_id=str(provider.id), now=now
            )

        assert result == {
            "signin_events": 2,
            "audit_events": 1,
            "unified_audit_events": 1,
            "threats": 1,
        }
        assert M365SignInLog.objects.count() == 2
        assert M365AuditLog.objects.get().activity_display_name == "Update user"
        assert M365UnifiedAuditLog.objects.get().operation == "FileAccessed"
        assert SectoThreat.objects.get().alert_key == "session-3"
        cursor = SectoLogCursor.objects.get(provider=provider)
        assert cursor.signin_cursor_at == now
        assert cursor.audit_cursor_at == now
        assert cursor.unified_audit_cursor_at == now

    def test_pull_m365_logs_skips_signins_when_tenant_lacks_premium_license(
        self, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[5]
        ProviderSecret.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            secret_type=ProviderSecret.TypeChoices.STATIC,
            name="m365",
            secret={
                "tenant_id": "00000000-0000-4000-8000-000000000000",
                "client_id": "11111111-1111-4111-8111-111111111111",
                "client_secret": "fake-client-secret",
            },
        )

        fake_credential = Mock()
        fake_credential.get_token.return_value.token = "fake-token"

        def response(body):
            mocked_response = Mock()
            mocked_response.json.return_value = body
            mocked_response.raise_for_status.return_value = None
            return mocked_response

        def forbidden_signins_response():
            mocked_response = response(
                {
                    "error": {
                        "code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                        "message": "Tenant is not a B2C tenant and doesn't have premium license",
                    }
                }
            )
            http_error = requests.HTTPError("403 Client Error: Forbidden")
            http_error.response = mocked_response
            mocked_response.raise_for_status.side_effect = http_error
            return mocked_response

        def get_response(url, params=None, **kwargs):
            if url.endswith("/auditLogs/signIns"):
                return forbidden_signins_response()
            if url.endswith("/auditLogs/directoryAudits"):
                return response({"value": []})
            if url.endswith("/subscriptions/list"):
                return response([{"contentType": params["contentType"]}])
            if url.endswith("/subscriptions/content"):
                return response([])
            raise AssertionError(f"Unexpected URL: {url}")

        with (
            patch(
                "secto.ingestion.ClientSecretCredential",
                return_value=fake_credential,
            ),
            patch("secto.ingestion.requests.get", side_effect=get_response),
        ):
            result = pull_m365_logs(
                tenant_id=str(tenant.id),
                provider_id=str(provider.id),
                now=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc),
            )

        assert result == {
            "signin_events": 0,
            "audit_events": 0,
            "unified_audit_events": 0,
            "threats": 0,
        }
        assert SectoLogCursor.objects.count() == 1


@pytest.mark.django_db
class TestSectoScheduling:
    def test_ensure_log_pull_schedule_creates_okta_five_minute_task(
        self, tenants_fixture
    ):
        tenant = tenants_fixture[0]
        provider = Provider.objects.create(
            tenant_id=tenant.id,
            provider=Provider.ProviderChoices.OKTA,
            uid="acme.okta.com",
            alias="okta",
        )

        periodic_task = ensure_log_pull_schedule(provider)
        repeated_task = ensure_log_pull_schedule(provider)

        assert repeated_task.id == periodic_task.id
        assert periodic_task.task == "secto-okta-log-pull"
        assert periodic_task.interval.every == 5
        assert periodic_task.interval.period == IntervalSchedule.MINUTES
        assert json.loads(periodic_task.kwargs) == {
            "tenant_id": str(provider.tenant_id),
            "provider_id": str(provider.id),
        }

    def test_ensure_m365_log_pull_schedule_creates_five_minute_task(
        self, providers_fixture
    ):
        provider = providers_fixture[5]

        periodic_task = ensure_log_pull_schedule(provider)
        repeated_task = ensure_log_pull_schedule(provider)

        assert repeated_task.id == periodic_task.id
        assert periodic_task.task == "secto-m365-log-pull"
        assert periodic_task.interval.every == 5
        assert periodic_task.interval.period == IntervalSchedule.MINUTES
        assert json.loads(periodic_task.kwargs) == {
            "tenant_id": str(provider.tenant_id),
            "provider_id": str(provider.id),
        }

    def test_daily_m365_scan_creates_log_pull_schedule(self, providers_fixture):
        provider = providers_fixture[5]

        with patch("tasks.tasks.perform_scheduled_scan_task.apply_async"):
            schedule_provider_scan(provider)

        assert PeriodicTask.objects.filter(
            name=f"secto-m365-log-pull-{provider.id}",
            task="secto-m365-log-pull",
            interval__every=5,
            interval__period=IntervalSchedule.MINUTES,
        ).exists()

    def test_daily_okta_scan_creates_scan_and_log_pull_schedule(self, tenants_fixture):
        tenant = tenants_fixture[0]
        provider = Provider.objects.create(
            tenant=tenant,
            provider=Provider.ProviderChoices.OKTA,
            uid="acme.okta.com",
            alias="okta",
        )

        with patch("tasks.tasks.perform_scheduled_scan_task.apply_async") as scan_task:
            schedule_provider_scan(provider)

        scan_task.assert_called_once()
        assert Scan.objects.filter(provider=provider).exists()
        assert PeriodicTask.objects.filter(
            name=f"secto-okta-log-pull-{provider.id}",
            task="secto-okta-log-pull",
            interval__every=5,
            interval__period=IntervalSchedule.MINUTES,
        ).exists()

    def test_manual_m365_scan_creates_log_pull_schedule(
        self, tenants_fixture, providers_fixture
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[5]
        scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
        )

        with (
            patch("tasks.tasks.perform_prowler_scan", return_value={"status": "ok"}),
            patch("tasks.tasks._perform_scan_complete_tasks"),
        ):
            perform_scan_task.run(
                tenant_id=str(tenant.id),
                provider_id=str(provider.id),
                scan_id=str(scan.id),
            )

        assert PeriodicTask.objects.filter(
            name=f"secto-m365-log-pull-{provider.id}",
            task="secto-m365-log-pull",
            interval__every=5,
            interval__period=IntervalSchedule.MINUTES,
        ).exists()

    def test_manual_okta_scan_creates_log_pull_schedule(self, tenants_fixture):
        tenant = tenants_fixture[0]
        provider = Provider.objects.create(
            tenant=tenant,
            provider=Provider.ProviderChoices.OKTA,
            uid="acme.okta.com",
            alias="okta",
        )
        scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
        )

        with (
            patch("tasks.tasks.perform_prowler_scan", return_value={"status": "ok"}),
            patch("tasks.tasks._perform_scan_complete_tasks"),
        ):
            perform_scan_task.run(
                tenant_id=str(tenant.id),
                provider_id=str(provider.id),
                scan_id=str(scan.id),
            )

        assert PeriodicTask.objects.filter(
            name=f"secto-okta-log-pull-{provider.id}",
            task="secto-okta-log-pull",
            interval__every=5,
            interval__period=IntervalSchedule.MINUTES,
        ).exists()
