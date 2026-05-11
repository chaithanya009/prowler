from unittest import mock

from prowler.providers.okta.services.user.user_service import OktaFactor, OktaUser
from tests.providers.okta.okta_fixtures import (
    USER_EMAIL,
    USER_ID,
    USER_LOGIN,
    set_mocked_okta_provider,
)


class Test_user_mfa_enabled:
    def test_no_users(self):
        user_client = mock.MagicMock
        user_client.users = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(
                "prowler.providers.okta.services.user.user_mfa_enabled.user_mfa_enabled.user_client",
                new=user_client,
            ),
        ):
            from prowler.providers.okta.services.user.user_mfa_enabled.user_mfa_enabled import (
                user_mfa_enabled,
            )

            result = user_mfa_enabled().execute()
            assert len(result) == 0

    def test_active_user_with_active_mfa_factor_passes(self):
        user_client = mock.MagicMock
        user_client.users = {
            USER_ID: OktaUser(
                id=USER_ID,
                login=USER_LOGIN,
                email=USER_EMAIL,
                status="ACTIVE",
                factors=[
                    OktaFactor(
                        id="factor-1",
                        factor_type="push",
                        provider="OKTA",
                        status="ACTIVE",
                    )
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(
                "prowler.providers.okta.services.user.user_mfa_enabled.user_mfa_enabled.user_client",
                new=user_client,
            ),
        ):
            from prowler.providers.okta.services.user.user_mfa_enabled.user_mfa_enabled import (
                user_mfa_enabled,
            )

            result = user_mfa_enabled().execute()
            assert len(result) == 1
            assert result[0].resource_id == USER_ID
            assert result[0].resource_name == USER_LOGIN
            assert result[0].status == "PASS"

    def test_active_user_without_active_mfa_factor_fails(self):
        user_client = mock.MagicMock
        user_client.users = {
            USER_ID: OktaUser(
                id=USER_ID,
                login=USER_LOGIN,
                email=USER_EMAIL,
                status="ACTIVE",
                factors=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(
                "prowler.providers.okta.services.user.user_mfa_enabled.user_mfa_enabled.user_client",
                new=user_client,
            ),
        ):
            from prowler.providers.okta.services.user.user_mfa_enabled.user_mfa_enabled import (
                user_mfa_enabled,
            )

            result = user_mfa_enabled().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_security_question_only_fails(self):
        user_client = mock.MagicMock
        user_client.users = {
            USER_ID: OktaUser(
                id=USER_ID,
                login=USER_LOGIN,
                email=USER_EMAIL,
                status="ACTIVE",
                factors=[
                    OktaFactor(
                        id="factor-1",
                        factor_type="question",
                        provider="OKTA",
                        status="ACTIVE",
                    )
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(
                "prowler.providers.okta.services.user.user_mfa_enabled.user_mfa_enabled.user_client",
                new=user_client,
            ),
        ):
            from prowler.providers.okta.services.user.user_mfa_enabled.user_mfa_enabled import (
                user_mfa_enabled,
            )

            result = user_mfa_enabled().execute()
            assert result[0].status == "FAIL"

    def test_inactive_user_is_skipped(self):
        user_client = mock.MagicMock
        user_client.users = {
            USER_ID: OktaUser(
                id=USER_ID,
                login=USER_LOGIN,
                email=USER_EMAIL,
                status="DEPROVISIONED",
                factors=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_okta_provider(),
            ),
            mock.patch(
                "prowler.providers.okta.services.user.user_mfa_enabled.user_mfa_enabled.user_client",
                new=user_client,
            ),
        ):
            from prowler.providers.okta.services.user.user_mfa_enabled.user_mfa_enabled import (
                user_mfa_enabled,
            )

            result = user_mfa_enabled().execute()
            assert len(result) == 0
