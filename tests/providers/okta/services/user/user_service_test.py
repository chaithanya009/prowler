from unittest.mock import MagicMock

from prowler.providers.okta.services.user.user_service import User
from tests.providers.okta.okta_fixtures import (
    ORG_URL,
    USER_EMAIL,
    USER_ID,
    USER_LOGIN,
    set_mocked_okta_provider,
)


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.raise_for_status = MagicMock()
    return response


class TestUserService:
    def test_lists_users_and_factors(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.side_effect = [
            _response(
                [
                    {
                        "id": USER_ID,
                        "status": "ACTIVE",
                        "profile": {
                            "login": USER_LOGIN,
                            "email": USER_EMAIL,
                        },
                    }
                ]
            ),
            _response(
                [
                    {
                        "id": "factor-1",
                        "factorType": "push",
                        "provider": "OKTA",
                        "status": "ACTIVE",
                    }
                ]
            ),
        ]

        service = User(provider)

        assert list(service.users) == [USER_ID]
        assert service.users[USER_ID].login == USER_LOGIN
        assert service.users[USER_ID].factors[0].factor_type == "push"
        assert service.users[USER_ID].factors[0].status == "ACTIVE"

    def test_paginates_users(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.side_effect = [
            _response(
                [
                    {
                        "id": USER_ID,
                        "status": "ACTIVE",
                        "profile": {"login": USER_LOGIN},
                    }
                ],
                headers={
                    "Link": '<https://example.okta.com/api/v1/users?after=abc>; rel="next"'
                },
            ),
            _response(
                [
                    {
                        "id": "00u2",
                        "status": "ACTIVE",
                        "profile": {"login": "bob@example.com"},
                    }
                ]
            ),
            _response([]),
            _response([]),
        ]

        service = User(provider)

        assert list(service.users) == [USER_ID, "00u2"]
        provider.session.http_session.get.assert_any_call(
            f"{ORG_URL}/api/v1/users?after=abc",
            timeout=30,
        )
