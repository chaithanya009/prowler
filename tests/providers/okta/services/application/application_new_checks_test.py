from unittest import mock

from prowler.providers.okta.services.application.application_service import (
    OktaAdminConsoleSettings,
    OktaApplication,
    OktaApplicationFeature,
    OktaOAuthClient,
)
from prowler.providers.okta.services.policy.policy_service import (
    OktaPolicy,
    OktaPolicyMapping,
)
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

APPLICATION_CLIENT = "prowler.providers.okta.services.application.application_client"
POLICY_CLIENT = "prowler.providers.okta.services.policy.policy_client"


class Test_application_new_checks:
    def test_weak_grants_disabled_passes_and_fails(self):
        result = _execute_app(
            "application_oauth_client_weak_grants_disabled",
            _application_client(clients=[_oauth_client(grants=["authorization_code"])]),
        )
        assert result[0].status == "PASS"

        result = _execute_app(
            "application_oauth_client_weak_grants_disabled",
            _application_client(clients=[_oauth_client(grants=["implicit"])]),
        )
        assert result[0].status == "FAIL"

    def test_no_oauth_clients_has_no_findings(self):
        result = _execute_app(
            "application_oauth_client_weak_grants_disabled",
            _application_client(clients=[]),
        )

        assert result == []

    def test_admin_console_session_lifetime_passes_and_fails(self):
        result = _execute_app(
            "application_admin_console_session_lifetime_bounded",
            _application_client(admin_settings=_admin_settings(lifetime=720, idle=15)),
        )
        assert result[0].status == "PASS"

        result = _execute_app(
            "application_admin_console_session_lifetime_bounded",
            _application_client(
                admin_settings=_admin_settings(lifetime=10080, idle=15)
            ),
        )
        assert result[0].status == "FAIL"

    def test_app_assignments_use_groups_passes_and_fails(self):
        result = _execute_app(
            "application_assignments_use_groups",
            _application_client(apps=[_app(groups=["group-1"], users=[])]),
        )
        assert result[0].status == "PASS"

        result = _execute_app(
            "application_assignments_use_groups",
            _application_client(apps=[_app(groups=[], users=["user-1"])]),
        )
        assert result[0].status == "FAIL"

    def test_api_service_apps_have_sign_on_policy_passes_and_fails(self):
        app = _app(settings={"oauthClient": {"application_type": "service"}})
        policy_client = _policy_client(mapped_app_ids={"app-1"})
        result = _execute_app(
            "application_api_service_apps_have_sign_on_policy",
            _application_client(apps=[app]),
            policy_client,
        )
        assert result[0].status == "PASS"

        policy_client = _policy_client(mapped_app_ids=set())
        result = _execute_app(
            "application_api_service_apps_have_sign_on_policy",
            _application_client(apps=[app]),
            policy_client,
        )
        assert result[0].status == "FAIL"

    def test_no_api_service_apps_has_no_findings(self):
        result = _execute_app(
            "application_api_service_apps_have_sign_on_policy",
            _application_client(apps=[_app()]),
            _policy_client(mapped_app_ids=set()),
        )

        assert result == []

    def test_okta_managed_apps_are_not_app_assignment_findings(self):
        result = _execute_app(
            "application_assignments_use_groups",
            _application_client(apps=[_app(name="saasure", groups=[], users=["user"])]),
        )

        assert result == []

    def test_provisioning_deactivation_enabled_passes_and_fails(self):
        result = _execute_app(
            "application_provisioning_deactivation_enabled",
            _application_client(
                apps=[_app(feature=_provisioning_feature(deactivation=True))]
            ),
        )
        assert result[0].status == "PASS"

        result = _execute_app(
            "application_provisioning_deactivation_enabled",
            _application_client(
                apps=[_app(feature=_provisioning_feature(deactivation=False))]
            ),
        )
        assert result[0].status == "FAIL"

    def test_no_provisioned_apps_has_no_findings(self):
        result = _execute_app(
            "application_provisioning_deactivation_enabled",
            _application_client(apps=[_app(feature=None)]),
        )

        assert result == []


def _execute_app(check_id, application_client, policy_client=None):
    module = f"prowler.providers.okta.services.application.{check_id}.{check_id}"
    clients = {APPLICATION_CLIENT: {"application_client": application_client}}
    if policy_client is not None:
        clients[POLICY_CLIENT] = {"policy_client": policy_client}

    with load_check_with_clients(module, clients) as loaded:
        return getattr(loaded, check_id)().execute()


def _application_client(clients=None, apps=None, admin_settings=None):
    client = mock.MagicMock()
    client.audit_config = {
        "max_admin_console_session_lifetime_minutes": 720,
        "max_admin_console_idle_minutes": 15,
    }
    client.clients = {oauth.id: oauth for oauth in clients or []}
    client.apps = {app.id: app for app in apps or []}
    client.admin_console_settings = admin_settings or _admin_settings(720, 15)
    return client


def _policy_client(mapped_app_ids):
    mappings = [
        OktaPolicyMapping(
            id=f"mapping-{app_id}",
            name=app_id,
            resource_id=app_id,
            resource_type="APP",
            href="",
        )
        for app_id in mapped_app_ids
    ]
    client = mock.MagicMock()
    client.access_policies = {
        "policy-1": OktaPolicy(
            id="policy-1",
            name="Policy",
            type="ACCESS_POLICY",
            status="ACTIVE",
            priority=1,
            system=False,
            mappings=mappings,
        )
    }
    return client


def _oauth_client(grants):
    return OktaOAuthClient(
        id="client-1",
        name="client",
        status="ACTIVE",
        application_type="web",
        grant_types=grants,
    )


def _admin_settings(lifetime, idle):
    return OktaAdminConsoleSettings(
        session_max_lifetime_minutes=lifetime,
        session_idle_timeout_minutes=idle,
    )


def _app(groups=None, users=None, settings=None, feature=None, name="custom"):
    return OktaApplication(
        id="app-1",
        name=name,
        label="Custom App",
        status="ACTIVE",
        sign_on_mode="OPENID_CONNECT",
        groups=groups or [],
        users=users or [],
        settings=settings or {},
        user_provisioning=feature,
    )


def _provisioning_feature(deactivation):
    status = "ENABLED" if deactivation else "DISABLED"
    return OktaApplicationFeature(
        id="USER_PROVISIONING",
        status="ENABLED",
        raw={"update": {"lifecycleDeactivate": {"status": status}}},
    )
