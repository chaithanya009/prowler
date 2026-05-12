from unittest import mock

from prowler.providers.okta.services.ratelimit.ratelimit_service import (
    OktaPerClientRateLimitSettings,
)
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

RATE_CLIENT = "prowler.providers.okta.services.ratelimit.ratelimit_client"


class Test_ratelimit_new_checks:
    def test_per_client_rate_limit_passes_and_fails(self):
        assert _execute("ENFORCE")[0].status == "PASS"
        assert _execute("DISABLE")[0].status == "FAIL"


def _execute(default_mode):
    client = mock.MagicMock()
    client.per_client_settings = OktaPerClientRateLimitSettings(
        default_mode=default_mode,
        use_case_mode_overrides={},
    )
    check_id = "ratelimit_per_client_enforced"
    module = f"prowler.providers.okta.services.ratelimit.{check_id}.{check_id}"
    with load_check_with_clients(
        module, {RATE_CLIENT: {"rate_limit_client": client}}
    ) as loaded:
        return getattr(loaded, check_id)().execute()
