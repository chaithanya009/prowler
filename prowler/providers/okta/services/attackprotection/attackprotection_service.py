from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.okta.exceptions.exceptions import OktaAPIError
from prowler.providers.okta.lib.service.service import OktaService
from prowler.providers.okta.models import OktaResource


class OktaUserLockoutSettings(BaseModel):
    """Okta Attack Protection user lockout settings."""

    id: str = "okta_user_lockout_settings"
    name: str = "Okta user lockout settings"
    prevent_brute_force_lockout_from_unknown_devices: bool
    location: str = "global"


class AttackProtection(OktaService):
    """Retrieve Okta Attack Protection settings."""

    def __init__(self, provider):
        super().__init__("AttackProtection", provider)
        self.resource = OktaResource(
            id="okta_attack_protection", name="Okta Attack Protection"
        )
        self.user_lockout_settings = self._get_user_lockout_settings()

    def _get_user_lockout_settings(self) -> OktaUserLockoutSettings:
        logger.info("AttackProtection - Retrieving user lockout settings...")
        path = "/attack-protection/api/v1/user-lockout-settings"
        try:
            settings = self._get(path).json()
        except OktaAPIError:
            settings = self._get_url(f"{_admin_org_url(self._org_url)}{path}").json()
        return OktaUserLockoutSettings(
            prevent_brute_force_lockout_from_unknown_devices=settings.get(
                "preventBruteForceLockoutFromUnknownDevices", False
            )
        )


def _admin_org_url(org_url: str) -> str:
    if org_url.endswith("-admin.okta.com"):
        return org_url
    if org_url.endswith(".okta.com"):
        return org_url.removesuffix(".okta.com") + "-admin.okta.com"
    return org_url
