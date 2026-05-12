from typing import Any

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.okta.exceptions.exceptions import OktaAPIError
from prowler.providers.okta.lib.service.service import OktaService
from prowler.providers.okta.models import OktaResource


class OktaAgent(BaseModel):
    """Okta directory agent."""

    id: str
    name: str
    version: str
    active: bool
    upgrade_required: bool
    is_latest_gaed_version: bool | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class OktaAgentPool(BaseModel):
    """Okta agent pool."""

    id: str
    name: str
    type: str
    agents: list[OktaAgent] = Field(default_factory=list)
    update_settings: dict[str, Any] = Field(default_factory=dict)
    location: str = "global"

    @property
    def has_update_settings(self) -> bool:
        return bool(self.update_settings)

    @property
    def below_minimum_supported_version(self) -> bool:
        minimum = self.update_settings.get("minimalSupportedVersion")
        if not minimum:
            return True
        return any(_version_less(agent.version, minimum) for agent in self.agents)

    @property
    def has_upgrade_required_agent(self) -> bool:
        return any(agent.upgrade_required for agent in self.agents)


class AgentPool(OktaService):
    """Retrieve Okta directory agent pools."""

    def __init__(self, provider):
        super().__init__("AgentPool", provider)
        self.resource = OktaResource(id="okta_agent_pools", name="Okta agent pools")
        self.ad_agent_pools = self._list_pools("AD")
        self.iwa_agent_pools = self._list_pools("IWA")

    def _list_pools(self, pool_type: str) -> dict[str, OktaAgentPool]:
        logger.info(f"AgentPool - Listing Okta {pool_type} agent pools...")
        try:
            response_pools = self._get_paginated(
                "/api/v1/agentPools",
                params={"poolType": pool_type, "limitPerPoolType": 200},
            )
        except OktaAPIError:
            logger.info(f"AgentPool - Skipping unavailable {pool_type} pools.")
            return {}

        pools = {}
        for pool in response_pools:
            pool_id = pool["id"]
            pools[pool_id] = OktaAgentPool(
                id=pool_id,
                name=pool.get("name", pool_id),
                type=str(pool.get("type", pool_type)).upper(),
                agents=_parse_agents(pool.get("agents")),
                update_settings=self._get_update_settings(pool_id),
            )
        return pools

    def _get_update_settings(self, pool_id: str) -> dict[str, Any]:
        try:
            return self._get(f"/api/v1/agentPools/{pool_id}/updates/settings").json()
        except OktaAPIError:
            return {}


def _parse_agents(value: Any) -> list[OktaAgent]:
    if isinstance(value, dict):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        values = []

    agents = []
    for agent in values:
        if not isinstance(agent, dict):
            continue
        agents.append(
            OktaAgent(
                id=agent.get("id", ""),
                name=agent.get("name", ""),
                version=agent.get("version", ""),
                active=agent.get("active", False),
                upgrade_required=agent.get("upgradeRequired", False),
                is_latest_gaed_version=agent.get("isLatestGAedVersion"),
                raw=agent,
            )
        )
    return agents


def _version_less(version: str, minimum: str) -> bool:
    return _version_parts(version) < _version_parts(minimum)


def _version_parts(version: str) -> tuple[int, ...]:
    parts = []
    for part in version.split("."):
        if not part.isdigit():
            break
        parts.append(int(part))
    return tuple(parts)
