from unittest.mock import MagicMock

from prowler.providers.okta.services.application.application_service import Application
from tests.providers.okta.okta_fixtures import ORG_URL, set_mocked_okta_provider


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.raise_for_status = MagicMock()
    return response


class TestApplicationService:
    def test_lists_oauth_clients(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.side_effect = [
            _response(
                [
                    {
                        "client_id": "client-1",
                        "client_name": "portal",
                        "application_type": "web",
                        "grant_types": ["authorization_code"],
                        "redirect_uris": ["https://app.example.com/callback"],
                    }
                ]
            ),
            _response([]),
            _response(
                {"sessionMaxLifetimeMinutes": 720, "sessionIdleTimeoutMinutes": 15}
            ),
        ]

        service = Application(provider)

        assert list(service.clients) == ["client-1"]
        assert service.clients["client-1"].name == "portal"
        assert service.clients["client-1"].status == "ACTIVE"
        assert service.clients["client-1"].grant_types == ["authorization_code"]
        provider.session.http_session.get.assert_any_call(
            f"{ORG_URL}/oauth2/v1/clients",
            params={"limit": 200},
            timeout=30,
        )

    def test_paginates_oauth_clients(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.side_effect = [
            _response(
                [{"client_id": "client-1", "client_name": "portal"}],
                headers={
                    "Link": '<https://example.okta.com/oauth2/v1/clients?after=abc>; rel="next"'
                },
            ),
            _response([{"client_id": "client-2", "client_name": "admin"}]),
            _response([]),
            _response(
                {"sessionMaxLifetimeMinutes": 720, "sessionIdleTimeoutMinutes": 15}
            ),
        ]

        service = Application(provider)

        assert list(service.clients) == ["client-1", "client-2"]
        provider.session.http_session.get.assert_any_call(
            f"{ORG_URL}/oauth2/v1/clients?after=abc",
            timeout=30,
        )

    def test_lists_apps_assignments_features_and_admin_console_settings(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.side_effect = [
            _response([]),
            _response(
                [
                    {
                        "id": "app-1",
                        "name": "custom",
                        "label": "Custom App",
                        "status": "ACTIVE",
                        "signOnMode": "OPENID_CONNECT",
                        "settings": {"oauthClient": {"application_type": "service"}},
                    }
                ]
            ),
            _response([{"id": "user-1"}]),
            _response([{"id": "group-1"}]),
            _response(
                {
                    "status": "ENABLED",
                    "update": {"lifecycleDeactivate": {"status": "ENABLED"}},
                }
            ),
            _response(
                {"sessionMaxLifetimeMinutes": 720, "sessionIdleTimeoutMinutes": 15}
            ),
        ]

        service = Application(provider)

        app = service.apps["app-1"]
        assert app.users == ["user-1"]
        assert app.groups == ["group-1"]
        assert app.is_api_service_app is True
        assert app.user_provisioning.status == "ENABLED"
        assert service.admin_console_settings.session_idle_timeout_minutes == 15
