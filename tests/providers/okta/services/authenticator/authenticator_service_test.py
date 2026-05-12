from unittest.mock import MagicMock

from prowler.providers.okta.services.authenticator.authenticator_service import (
    Authenticator,
)
from tests.providers.okta.okta_fixtures import ORG_URL, set_mocked_okta_provider


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.raise_for_status = MagicMock()
    return response


class TestAuthenticatorService:
    def test_lists_authenticators_methods_and_org_factors(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.side_effect = [
            _response([{"id": "aut-1", "key": "phone_number", "status": "ACTIVE"}]),
            _response([{"type": "sms", "status": "ACTIVE"}]),
            _response(
                [
                    {
                        "factorType": "question",
                        "provider": "OKTA",
                        "status": "INACTIVE",
                    }
                ]
            ),
        ]

        service = Authenticator(provider)

        assert service.has_active_method("sms") is True
        assert service.has_active_method("question") is False
        assert "question" in service.org_factors
        assert list(service.authenticators) == ["aut-1"]
        provider.session.http_session.get.assert_any_call(
            f"{ORG_URL}/api/v1/authenticators",
            params={"limit": 200},
            timeout=30,
        )
