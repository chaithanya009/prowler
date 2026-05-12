from unittest.mock import MagicMock

from prowler.providers.okta.services.org.org_service import Org
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.raise_for_status = MagicMock()
    return response


class TestOrgService:
    def test_gets_support_settings_and_cases(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.side_effect = [
            _response({"support": "DISABLED"}),
            _response({"supportCases": [{"selfAssigned": {"status": "APPROVED"}}]}),
        ]

        service = Org(provider)

        assert service.support_settings.support == "DISABLED"
        assert service.support_settings.has_standing_access is True
