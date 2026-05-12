from unittest import mock

from prowler.providers.okta.models import OktaResource
from prowler.providers.okta.services.apitoken.apitoken_service import OktaApiToken
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

CHECK_MODULE = "prowler.providers.okta.services.apitoken.apitoken_network_restricted.apitoken_network_restricted"
CLIENT_MODULE = "prowler.providers.okta.services.apitoken.apitoken_client"


class Test_apitoken_network_restricted:
    def test_no_active_tokens_passes(self):
        client = mock.MagicMock()
        client.resource = OktaResource(
            id="okta_api_tokens", name="Okta SSWS API tokens"
        )
        client.tokens = {}

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"api_token_client": client}}
        ) as module:
            result = module.apitoken_network_restricted().execute()

        assert len(result) == 1
        assert result[0].resource_id == "okta_api_tokens"
        assert result[0].status == "PASS"

    def test_restricted_active_token_passes(self):
        client = mock.MagicMock()
        client.tokens = {
            "token-1": OktaApiToken(
                id="token-1",
                name="ci-token",
                user_id="00u1",
                status="ACTIVE",
                network_connection="ZONE",
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"api_token_client": client}}
        ) as module:
            result = module.apitoken_network_restricted().execute()

        assert len(result) == 1
        assert result[0].resource_id == "token-1"
        assert result[0].status == "PASS"

    def test_anywhere_active_token_fails(self):
        client = mock.MagicMock()
        client.tokens = {
            "token-1": OktaApiToken(
                id="token-1",
                name="ci-token",
                user_id="00u1",
                status="ACTIVE",
                network_connection="ANYWHERE",
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"api_token_client": client}}
        ) as module:
            result = module.apitoken_network_restricted().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_inactive_anywhere_token_is_ignored(self):
        client = mock.MagicMock()
        client.resource = OktaResource(
            id="okta_api_tokens", name="Okta SSWS API tokens"
        )
        client.tokens = {
            "token-1": OktaApiToken(
                id="token-1",
                name="old-token",
                user_id="00u1",
                status="INACTIVE",
                network_connection="ANYWHERE",
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"api_token_client": client}}
        ) as module:
            result = module.apitoken_network_restricted().execute()

        assert len(result) == 1
        assert result[0].resource_id == "okta_api_tokens"
        assert result[0].status == "PASS"
