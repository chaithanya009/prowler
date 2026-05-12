from unittest.mock import MagicMock

from prowler.providers.okta.services.zone.zone_service import Zone
from tests.providers.okta.okta_fixtures import ORG_URL, set_mocked_okta_provider


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.raise_for_status = MagicMock()
    return response


class TestZoneService:
    def test_lists_network_zones(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.return_value = _response(
            [
                {
                    "id": "zone-1",
                    "name": "Tor",
                    "status": "ACTIVE",
                    "type": "DYNAMIC_V2",
                    "usage": "BLOCKLIST",
                    "ipServiceCategories": ["TOR"],
                    "locations": [{"country": "KP"}],
                }
            ]
        )

        service = Zone(provider)

        assert service.has_tor_block_zone() is True
        assert service.has_country_block_zone() is True
        provider.session.http_session.get.assert_called_once_with(
            f"{ORG_URL}/api/v1/zones",
            params={"limit": 200},
            timeout=30,
        )
