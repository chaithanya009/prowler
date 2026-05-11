import os
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.common.models import Connection
from prowler.providers.okta.exceptions.exceptions import (
    OktaAuthenticationError,
    OktaCredentialsError,
)
from prowler.providers.okta.models import OktaIdentityInfo, OktaSession
from prowler.providers.okta.okta_provider import OktaProvider
from tests.providers.okta.okta_fixtures import (
    API_TOKEN,
    ORG_URL,
    USER_EMAIL,
    USER_ID,
    USER_LOGIN,
)


class TestOktaProviderSetupSession:
    def test_setup_session_with_env_vars(self):
        with mock.patch.dict(
            os.environ,
            {"OKTA_API_TOKEN": API_TOKEN, "OKTA_ORG_URL": ORG_URL},
            clear=True,
        ):
            session = OktaProvider.setup_session()

        assert isinstance(session, OktaSession)
        assert session.api_token == API_TOKEN
        assert session.org_url == ORG_URL
        assert session.http_session is not None

    def test_setup_session_with_parameters(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            session = OktaProvider.setup_session(
                api_token=API_TOKEN,
                org_url=f"{ORG_URL}/",
            )

        assert session.api_token == API_TOKEN
        assert session.org_url == ORG_URL

    def test_setup_session_without_token_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with pytest.raises(OktaCredentialsError):
                OktaProvider.setup_session(org_url=ORG_URL)

    def test_setup_session_without_org_url_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with pytest.raises(OktaCredentialsError):
                OktaProvider.setup_session(api_token=API_TOKEN)


class TestOktaProviderSetupIdentity:
    def test_setup_identity(self):
        session = OktaSession(
            org_url=ORG_URL,
            api_token=API_TOKEN,
            http_session=MagicMock(),
        )
        response = MagicMock()
        response.json.return_value = {
            "id": USER_ID,
            "profile": {
                "login": USER_LOGIN,
                "email": USER_EMAIL,
            },
        }
        response.raise_for_status = MagicMock()
        session.http_session.get = MagicMock(return_value=response)

        identity = OktaProvider.setup_identity(session)

        assert isinstance(identity, OktaIdentityInfo)
        assert identity.user_id == USER_ID
        assert identity.login == USER_LOGIN
        assert identity.email == USER_EMAIL
        assert identity.org_url == ORG_URL
        session.http_session.get.assert_called_once_with(
            f"{ORG_URL}/api/v1/users/me",
            timeout=30,
        )


class TestOktaProviderValidateCredentials:
    def test_valid_credentials(self):
        session = OktaSession(
            org_url=ORG_URL,
            api_token=API_TOKEN,
            http_session=MagicMock(),
        )
        response = MagicMock()
        response.status_code = 200
        response.raise_for_status = MagicMock()
        session.http_session.get = MagicMock(return_value=response)

        OktaProvider.validate_credentials(session)

    def test_invalid_token_raises(self):
        session = OktaSession(
            org_url=ORG_URL,
            api_token="invalid",
            http_session=MagicMock(),
        )
        response = MagicMock()
        response.status_code = 401
        session.http_session.get = MagicMock(return_value=response)

        with pytest.raises(OktaAuthenticationError):
            OktaProvider.validate_credentials(session)


class TestOktaProviderTestConnection:
    @patch.object(OktaProvider, "validate_credentials")
    @patch.object(OktaProvider, "setup_session")
    def test_successful_connection(self, mock_setup_session, mock_validate):
        mock_setup_session.return_value = OktaSession(
            org_url=ORG_URL,
            api_token=API_TOKEN,
            http_session=MagicMock(),
        )
        mock_validate.return_value = None

        result = OktaProvider.test_connection(raise_on_exception=False)

        assert isinstance(result, Connection)
        assert result.is_connected is True

    @patch.object(OktaProvider, "setup_session")
    def test_failed_connection(self, mock_setup_session):
        mock_setup_session.side_effect = OktaCredentialsError(message="missing")

        result = OktaProvider.test_connection(raise_on_exception=False)

        assert isinstance(result, Connection)
        assert result.is_connected is False
        assert result.error is not None
