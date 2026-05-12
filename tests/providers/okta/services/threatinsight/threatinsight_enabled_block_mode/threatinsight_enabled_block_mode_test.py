from unittest import mock

from prowler.providers.okta.services.threatinsight.threatinsight_service import (
    ThreatInsightConfiguration,
)
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

CHECK_MODULE = "prowler.providers.okta.services.threatinsight.threatinsight_enabled_block_mode.threatinsight_enabled_block_mode"
CLIENT_MODULE = "prowler.providers.okta.services.threatinsight.threatinsight_client"


class Test_threatinsight_enabled_block_mode:
    def test_block_mode_passes(self):
        client = mock.MagicMock()
        client.configuration = ThreatInsightConfiguration(action="block")

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"threatinsight_client": client}}
        ) as module:
            result = module.threatinsight_enabled_block_mode().execute()

        assert len(result) == 1
        assert result[0].resource_id == "threatinsight_configuration"
        assert result[0].resource_name == "ThreatInsight configuration"
        assert result[0].status == "PASS"

    def test_audit_mode_fails(self):
        client = mock.MagicMock()
        client.configuration = ThreatInsightConfiguration(action="audit")

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"threatinsight_client": client}}
        ) as module:
            result = module.threatinsight_enabled_block_mode().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
