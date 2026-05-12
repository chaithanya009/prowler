from unittest import mock

from prowler.providers.okta.services.user.user_service import OktaFactor, OktaUser
from tests.providers.okta.okta_check_test_utils import load_check_with_clients
from tests.providers.okta.okta_fixtures import USER_EMAIL, USER_ID, USER_LOGIN

CHECK_MODULE = "prowler.providers.okta.services.user.user_admins_two_active_factors.user_admins_two_active_factors"
CLIENT_MODULE = "prowler.providers.okta.services.user.user_client"


class Test_user_admins_two_active_factors:
    def test_admin_with_two_active_factors_passes(self):
        client = mock.MagicMock()
        client.users = {
            USER_ID: OktaUser(
                id=USER_ID,
                login=USER_LOGIN,
                email=USER_EMAIL,
                status="ACTIVE",
                roles=["ORG_ADMIN"],
                factors=[_factor("factor-1", "push"), _factor("factor-2", "webauthn")],
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"user_client": client}}
        ) as module:
            result = module.user_admins_two_active_factors().execute()

        assert len(result) == 1
        assert result[0].resource_id == USER_ID
        assert result[0].resource_name == USER_LOGIN
        assert result[0].status == "PASS"

    def test_admin_with_one_active_factor_fails(self):
        client = mock.MagicMock()
        client.users = {
            USER_ID: OktaUser(
                id=USER_ID,
                login=USER_LOGIN,
                email=USER_EMAIL,
                status="ACTIVE",
                roles=["APP_ADMIN"],
                factors=[_factor("factor-1", "push")],
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"user_client": client}}
        ) as module:
            result = module.user_admins_two_active_factors().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_non_admin_user_is_ignored(self):
        client = mock.MagicMock()
        client.users = {
            USER_ID: OktaUser(
                id=USER_ID,
                login=USER_LOGIN,
                email=USER_EMAIL,
                status="ACTIVE",
                roles=[],
                factors=[],
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"user_client": client}}
        ) as module:
            result = module.user_admins_two_active_factors().execute()

        assert len(result) == 0


def _factor(factor_id: str, factor_type: str) -> OktaFactor:
    return OktaFactor(
        id=factor_id,
        factor_type=factor_type,
        provider="OKTA",
        status="ACTIVE",
    )
