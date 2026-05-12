from unittest.mock import MagicMock

import requests

from prowler.providers.okta.services.attackprotection.attackprotection_service import (
    AttackProtection,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.raise_for_status = MagicMock()
    return response


class TestAttackProtectionService:
    def test_gets_user_lockout_settings(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.return_value = _response(
            {"preventBruteForceLockoutFromUnknownDevices": True}
        )

        service = AttackProtection(provider)

        assert (
            service.user_lockout_settings.prevent_brute_force_lockout_from_unknown_devices
            is True
        )

    def test_retries_user_lockout_settings_on_admin_domain(self):
        provider = set_mocked_okta_provider(audit_config={"max_retries": 0})
        provider.session.http_session.get.side_effect = [
            _not_found_response(),
            _response({"preventBruteForceLockoutFromUnknownDevices": True}),
        ]

        service = AttackProtection(provider)

        assert (
            service.user_lockout_settings.prevent_brute_force_lockout_from_unknown_devices
            is True
        )


def _not_found_response():
    response = _response({"errorSummary": "Not found"})
    response.status_code = 404
    response.raise_for_status.side_effect = requests.exceptions.HTTPError("404")
    return response
