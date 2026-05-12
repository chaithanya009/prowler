from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.threatinsight.threatinsight_service import (
    ThreatInsight,
)

threatinsight_client = ThreatInsight(Provider.get_global_provider())
