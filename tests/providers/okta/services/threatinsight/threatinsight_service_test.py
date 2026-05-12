from unittest.mock import MagicMock

from prowler.providers.okta.services.threatinsight.threatinsight_service import (
    ThreatInsight,
)
from tests.providers.okta.okta_fixtures import ORG_URL, set_mocked_okta_provider


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.raise_for_status = MagicMock()
    return response


class TestThreatInsightService:
    def test_gets_configuration(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.return_value = _response({"action": "block"})

        service = ThreatInsight(provider)

        assert service.configuration.action == "block"
        provider.session.http_session.get.assert_called_once_with(
            f"{ORG_URL}/api/v1/threats/configuration",
            timeout=30,
        )
