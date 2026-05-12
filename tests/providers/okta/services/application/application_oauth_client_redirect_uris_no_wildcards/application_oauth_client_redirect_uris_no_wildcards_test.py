from unittest import mock

from prowler.providers.okta.services.application.application_service import (
    OktaOAuthClient,
)
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

CHECK_MODULE = "prowler.providers.okta.services.application.application_oauth_client_redirect_uris_no_wildcards.application_oauth_client_redirect_uris_no_wildcards"
CLIENT_MODULE = "prowler.providers.okta.services.application.application_client"


class Test_application_oauth_client_redirect_uris_no_wildcards:
    def test_client_without_wildcard_redirect_uri_passes(self):
        client = mock.MagicMock()
        client.clients = {
            "client-1": OktaOAuthClient(
                id="client-1",
                name="portal",
                status="ACTIVE",
                application_type="web",
                redirect_uris=["https://app.example.com/callback"],
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"application_client": client}}
        ) as module:
            result = (
                module.application_oauth_client_redirect_uris_no_wildcards().execute()
            )

        assert len(result) == 1
        assert result[0].resource_id == "client-1"
        assert result[0].status == "PASS"

    def test_client_with_wildcard_redirect_uri_fails(self):
        client = mock.MagicMock()
        client.clients = {
            "client-1": OktaOAuthClient(
                id="client-1",
                name="portal",
                status="ACTIVE",
                application_type="web",
                redirect_uris=["https://*.example.com/callback"],
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"application_client": client}}
        ) as module:
            result = (
                module.application_oauth_client_redirect_uris_no_wildcards().execute()
            )

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_path_wildcard_does_not_fail(self):
        client = mock.MagicMock()
        client.clients = {
            "client-1": OktaOAuthClient(
                id="client-1",
                name="portal",
                status="ACTIVE",
                application_type="web",
                redirect_uris=["https://app.example.com/*"],
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"application_client": client}}
        ) as module:
            result = (
                module.application_oauth_client_redirect_uris_no_wildcards().execute()
            )

        assert result[0].status == "PASS"

    def test_inactive_client_is_ignored(self):
        client = mock.MagicMock()
        client.clients = {
            "client-1": OktaOAuthClient(
                id="client-1",
                name="portal",
                status="INACTIVE",
                application_type="web",
                redirect_uris=["https://*.example.com/callback"],
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"application_client": client}}
        ) as module:
            result = (
                module.application_oauth_client_redirect_uris_no_wildcards().execute()
            )

        assert len(result) == 0
