from unittest.mock import MagicMock

from prowler.providers.okta.services.ratelimit.ratelimit_service import RateLimit
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.raise_for_status = MagicMock()
    return response


class TestRateLimitService:
    def test_gets_per_client_rate_limit_settings(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.return_value = _response(
            {"defaultMode": "ENFORCE"}
        )

        service = RateLimit(provider)

        assert service.per_client_settings.enforced is True
