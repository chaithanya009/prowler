from unittest import mock

from prowler.providers.okta.services.attackprotection.attackprotection_service import (
    OktaUserLockoutSettings,
)
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

ATTACK_CLIENT = (
    "prowler.providers.okta.services.attackprotection.attackprotection_client"
)


class Test_attackprotection_new_checks:
    def test_unknown_device_lockout_prevention_passes_and_fails(self):
        assert _execute(True)[0].status == "PASS"
        assert _execute(False)[0].status == "FAIL"


def _execute(enabled):
    client = mock.MagicMock()
    client.user_lockout_settings = OktaUserLockoutSettings(
        prevent_brute_force_lockout_from_unknown_devices=enabled
    )
    check_id = "attackprotection_unknown_device_lockout_prevention_enabled"
    module = f"prowler.providers.okta.services.attackprotection.{check_id}.{check_id}"
    with load_check_with_clients(
        module, {ATTACK_CLIENT: {"attack_protection_client": client}}
    ) as loaded:
        return getattr(loaded, check_id)().execute()
