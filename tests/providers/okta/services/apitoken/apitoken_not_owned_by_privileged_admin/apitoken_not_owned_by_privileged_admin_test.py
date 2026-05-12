from unittest import mock

from prowler.providers.okta.models import OktaResource
from prowler.providers.okta.services.apitoken.apitoken_service import OktaApiToken
from prowler.providers.okta.services.user.user_service import OktaUser
from tests.providers.okta.okta_check_test_utils import load_check_with_clients
from tests.providers.okta.okta_fixtures import USER_EMAIL, USER_ID, USER_LOGIN

CHECK_MODULE = "prowler.providers.okta.services.apitoken.apitoken_not_owned_by_privileged_admin.apitoken_not_owned_by_privileged_admin"
API_TOKEN_CLIENT_MODULE = "prowler.providers.okta.services.apitoken.apitoken_client"
USER_CLIENT_MODULE = "prowler.providers.okta.services.user.user_client"


class Test_apitoken_not_owned_by_privileged_admin:
    def test_no_active_tokens_passes(self):
        api_token_client = mock.MagicMock()
        api_token_client.resource = OktaResource(
            id="okta_api_tokens", name="Okta SSWS API tokens"
        )
        api_token_client.tokens = {}
        user_client = mock.MagicMock()
        user_client.users = {}

        with load_check_with_clients(
            CHECK_MODULE,
            {
                API_TOKEN_CLIENT_MODULE: {"api_token_client": api_token_client},
                USER_CLIENT_MODULE: {"user_client": user_client},
            },
        ) as module:
            result = module.apitoken_not_owned_by_privileged_admin().execute()

        assert len(result) == 1
        assert result[0].resource_id == "okta_api_tokens"
        assert result[0].status == "PASS"

    def test_token_owned_by_regular_admin_passes(self):
        api_token_client = _api_token_client()
        user_client = _user_client(["APP_ADMIN"])

        with load_check_with_clients(
            CHECK_MODULE,
            {
                API_TOKEN_CLIENT_MODULE: {"api_token_client": api_token_client},
                USER_CLIENT_MODULE: {"user_client": user_client},
            },
        ) as module:
            result = module.apitoken_not_owned_by_privileged_admin().execute()

        assert len(result) == 1
        assert result[0].resource_id == "token-1"
        assert result[0].status == "PASS"

    def test_token_owned_by_super_admin_fails(self):
        api_token_client = _api_token_client()
        user_client = _user_client(["SUPER_ADMIN"])

        with load_check_with_clients(
            CHECK_MODULE,
            {
                API_TOKEN_CLIENT_MODULE: {"api_token_client": api_token_client},
                USER_CLIENT_MODULE: {"user_client": user_client},
            },
        ) as module:
            result = module.apitoken_not_owned_by_privileged_admin().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_token_owned_by_org_admin_fails(self):
        api_token_client = _api_token_client()
        user_client = _user_client(["ORG_ADMIN"])

        with load_check_with_clients(
            CHECK_MODULE,
            {
                API_TOKEN_CLIENT_MODULE: {"api_token_client": api_token_client},
                USER_CLIENT_MODULE: {"user_client": user_client},
            },
        ) as module:
            result = module.apitoken_not_owned_by_privileged_admin().execute()

        assert result[0].status == "FAIL"

    def test_inactive_privileged_token_is_ignored(self):
        api_token_client = mock.MagicMock()
        api_token_client.resource = OktaResource(
            id="okta_api_tokens", name="Okta SSWS API tokens"
        )
        api_token_client.tokens = {
            "token-1": OktaApiToken(
                id="token-1",
                name="old-token",
                user_id=USER_ID,
                status="INACTIVE",
                network_connection="ANYWHERE",
            )
        }
        user_client = _user_client(["SUPER_ADMIN"])

        with load_check_with_clients(
            CHECK_MODULE,
            {
                API_TOKEN_CLIENT_MODULE: {"api_token_client": api_token_client},
                USER_CLIENT_MODULE: {"user_client": user_client},
            },
        ) as module:
            result = module.apitoken_not_owned_by_privileged_admin().execute()

        assert result[0].resource_id == "okta_api_tokens"
        assert result[0].status == "PASS"


def _api_token_client():
    client = mock.MagicMock()
    client.tokens = {
        "token-1": OktaApiToken(
            id="token-1",
            name="ci-token",
            user_id=USER_ID,
            status="ACTIVE",
            network_connection="ZONE",
        )
    }
    return client


def _user_client(roles: list[str]):
    client = mock.MagicMock()
    client.users = {
        USER_ID: OktaUser(
            id=USER_ID,
            login=USER_LOGIN,
            email=USER_EMAIL,
            status="ACTIVE",
            roles=roles,
        )
    }
    return client
