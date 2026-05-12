from unittest.mock import MagicMock

from prowler.providers.okta.services.apitoken.apitoken_service import ApiToken
from tests.providers.okta.okta_fixtures import (
    ORG_URL,
    USER_ID,
    set_mocked_okta_provider,
)


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.raise_for_status = MagicMock()
    return response


class TestApiTokenService:
    def test_lists_tokens(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.return_value = _response(
            [
                {
                    "id": "token-1",
                    "name": "ci-token",
                    "userId": USER_ID,
                    "status": "ACTIVE",
                    "network": {"connection": "ZONE"},
                }
            ]
        )

        service = ApiToken(provider)

        assert list(service.tokens) == ["token-1"]
        assert service.tokens["token-1"].user_id == USER_ID
        assert service.tokens["token-1"].network_connection == "ZONE"
        provider.session.http_session.get.assert_called_once_with(
            f"{ORG_URL}/api/v1/api-tokens",
            params={"limit": 200},
            timeout=30,
        )

    def test_defaults_missing_token_status_to_active(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.return_value = _response(
            [
                {
                    "id": "token-1",
                    "name": "ci-token",
                    "userId": USER_ID,
                    "network": {"connection": "ANYWHERE"},
                }
            ]
        )

        service = ApiToken(provider)

        assert service.tokens["token-1"].status == "ACTIVE"
