from typing import Any

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService
from prowler.providers.okta.models import OktaResource

RISKY_IP_SERVICE_CATEGORIES = frozenset(
    {"ANONYMIZER", "PROXY", "VPN", "TOR", "TOR_ANONYMIZER"}
)


class OktaNetworkZone(BaseModel):
    """Okta network zone."""

    id: str
    name: str
    status: str
    type: str
    usage: str
    proxy_type: str
    ip_service_categories: list[str] = Field(default_factory=list)
    countries: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    location: str = "global"

    @property
    def blocks(self) -> bool:
        return self.status == "ACTIVE" and self.usage == "BLOCKLIST"

    @property
    def blocks_tor(self) -> bool:
        if not self.blocks:
            return False
        values = {self.proxy_type, *self.ip_service_categories}
        return "TOR" in values or "TOR_ANONYMIZER" in values

    @property
    def blocks_risky_proxy(self) -> bool:
        if not self.blocks:
            return False
        values = {self.proxy_type, *self.ip_service_categories}
        return bool(values & RISKY_IP_SERVICE_CATEGORIES)


class Zone(OktaService):
    """Retrieve Okta network zones."""

    def __init__(self, provider):
        super().__init__("Zone", provider)
        self.resource = OktaResource(id="okta_network_zones", name="Okta network zones")
        self.zones = self._list_zones()

    def has_tor_block_zone(self) -> bool:
        for zone in self.zones.values():
            if zone.blocks_tor:
                return True
        return False

    def has_country_block_zone(self) -> bool:
        for zone in self.zones.values():
            if zone.blocks and zone.countries:
                return True
        return False

    def has_risky_proxy_block_zone(self) -> bool:
        for zone in self.zones.values():
            if zone.blocks_risky_proxy:
                return True
        return False

    def _list_zones(self) -> dict[str, OktaNetworkZone]:
        logger.info("Zone - Listing Okta network zones...")
        response_zones = self._get_paginated("/api/v1/zones", params={"limit": 200})

        zones = {}
        for zone in response_zones:
            zone_id = zone["id"]
            zones[zone_id] = OktaNetworkZone(
                id=zone_id,
                name=zone.get("name", zone_id),
                status=str(zone.get("status", "ACTIVE")).upper(),
                type=str(zone.get("type", "")).upper(),
                usage=str(zone.get("usage", "")).upper(),
                proxy_type=str(zone.get("proxyType", "")).upper(),
                ip_service_categories=[
                    str(category).upper()
                    for category in zone.get("ipServiceCategories", [])
                ],
                countries=_countries(zone),
                raw=zone,
            )
        return zones


def _countries(zone: dict[str, Any]) -> list[str]:
    countries = []
    for location in zone.get("locations", []):
        country = location.get("country") if isinstance(location, dict) else None
        if country:
            countries.append(str(country).upper())
    return countries
