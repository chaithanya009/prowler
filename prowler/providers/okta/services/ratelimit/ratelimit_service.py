from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService


class OktaPerClientRateLimitSettings(BaseModel):
    """Okta per-client rate limit settings."""

    id: str = "okta_per_client_rate_limits"
    name: str = "Okta per-client rate limits"
    default_mode: str
    use_case_mode_overrides: dict[str, str]
    location: str = "global"

    @property
    def enforced(self) -> bool:
        if self.default_mode != "ENFORCE":
            return False
        return all(mode == "ENFORCE" for mode in self.use_case_mode_overrides.values())


class RateLimit(OktaService):
    """Retrieve Okta rate limit settings."""

    def __init__(self, provider):
        super().__init__("RateLimit", provider)
        self.per_client_settings = self._get_per_client_settings()

    def _get_per_client_settings(self) -> OktaPerClientRateLimitSettings:
        logger.info("RateLimit - Retrieving per-client rate limit settings...")
        settings = self._get("/api/v1/rate-limit-settings/per-client").json()
        return OktaPerClientRateLimitSettings(
            default_mode=str(settings.get("defaultMode", "DISABLE")).upper(),
            use_case_mode_overrides={
                use_case: str(mode).upper()
                for use_case, mode in settings.get("useCaseModeOverrides", {}).items()
            },
        )
