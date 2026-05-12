from unittest import mock

from prowler.providers.okta.models import OktaResource
from prowler.providers.okta.services.org.org_service import OktaSupportSettings
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

ORG_CLIENT = "prowler.providers.okta.services.org.org_client"


class Test_org_new_checks:
    def test_support_access_not_preapproved_passes(self):
        result = _execute(OktaSupportSettings(support="DISABLED"))

        assert result[0].status == "PASS"

    def test_support_access_preapproved_fails(self):
        result = _execute(
            OktaSupportSettings(
                support="DISABLED",
                cases=[{"selfAssigned": {"status": "APPROVED"}}],
            )
        )

        assert result[0].status == "FAIL"

    def test_temporary_support_access_with_expiration_passes(self):
        result = _execute(
            OktaSupportSettings(
                support="ENABLED",
                expiration="2026-05-12T12:00:00.000Z",
                case_number="1000001",
                cases=[
                    {
                        "impersonation": {
                            "status": "ENABLED",
                            "expiration": "2026-05-12T12:00:00.000Z",
                        }
                    }
                ],
            )
        )

        assert result[0].status == "PASS"


def _execute(settings):
    client = mock.MagicMock()
    client.resource = OktaResource(id="okta_org", name="Okta organization")
    client.support_settings = settings
    check_id = "org_support_access_not_preapproved"
    module = f"prowler.providers.okta.services.org.{check_id}.{check_id}"
    with load_check_with_clients(
        module, {ORG_CLIENT: {"org_client": client}}
    ) as loaded:
        return getattr(loaded, check_id)().execute()
