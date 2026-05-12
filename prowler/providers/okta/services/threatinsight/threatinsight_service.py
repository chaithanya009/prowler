from pydantic import BaseModel

from prowler.providers.okta.lib.service.service import OktaService


class ThreatInsightConfiguration(BaseModel):
    """Okta ThreatInsight configuration."""

    id: str = "threatinsight_configuration"
    name: str = "ThreatInsight configuration"
    action: str
    location: str = "global"


class ThreatInsight(OktaService):
    """Retrieve Okta ThreatInsight configuration."""

    def __init__(self, provider):
        super().__init__("ThreatInsight", provider)
        self.configuration = self._get_configuration()

    def _get_configuration(self) -> ThreatInsightConfiguration:
        response = self._get("/api/v1/threats/configuration")
        configuration = response.json()

        return ThreatInsightConfiguration(
            action=str(configuration.get("action", "none")).lower()
        )
