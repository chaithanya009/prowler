from unittest import mock

from prowler.providers.okta.models import OktaResource
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

ZONE_CLIENT = "prowler.providers.okta.services.zone.zone_client"


class Test_zone_new_checks:
    def test_tor_block_zone_passes_and_fails(self):
        assert (
            _execute("zone_tor_anonymizer_block_configured", tor=True)[0].status
            == "PASS"
        )
        assert (
            _execute("zone_tor_anonymizer_block_configured", tor=False)[0].status
            == "FAIL"
        )

    def test_country_block_zone_passes_and_fails(self):
        assert (
            _execute("zone_country_block_configured", country=True)[0].status == "PASS"
        )
        assert (
            _execute("zone_country_block_configured", country=False)[0].status == "FAIL"
        )

    def test_risky_proxy_block_zone_passes_and_fails(self):
        assert (
            _execute("zone_risky_proxy_block_configured", proxy=True)[0].status
            == "PASS"
        )
        assert (
            _execute("zone_risky_proxy_block_configured", proxy=False)[0].status
            == "FAIL"
        )


def _execute(check_id, tor=False, country=False, proxy=False):
    client = mock.MagicMock()
    client.resource = OktaResource(id="okta_network_zones", name="Okta network zones")
    client.has_tor_block_zone.return_value = tor
    client.has_country_block_zone.return_value = country
    client.has_risky_proxy_block_zone.return_value = proxy
    module = f"prowler.providers.okta.services.zone.{check_id}.{check_id}"
    with load_check_with_clients(
        module, {ZONE_CLIENT: {"zone_client": client}}
    ) as loaded:
        return getattr(loaded, check_id)().execute()
