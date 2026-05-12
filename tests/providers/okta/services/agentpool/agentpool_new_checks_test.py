from unittest import mock

from prowler.providers.okta.models import OktaResource
from prowler.providers.okta.services.agentpool.agentpool_service import (
    OktaAgent,
    OktaAgentPool,
)
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

AGENT_CLIENT = "prowler.providers.okta.services.agentpool.agentpool_client"


class Test_agentpool_new_checks:
    def test_ad_agents_supported_version_passes_and_fails(self):
        pool = _ad_pool(version="3.20.0", minimum="3.19.0")
        result = _execute_ad(pool)
        assert result[0].status == "PASS"

        pool = _ad_pool(version="3.18.0", minimum="3.19.0")
        result = _execute_ad(pool)
        assert result[0].status == "FAIL"

    def test_iwa_absent_passes_and_fails(self):
        result = _execute_iwa([])
        assert result[0].status == "PASS"

        result = _execute_iwa([_ad_pool()])
        assert result[0].status == "FAIL"


def _execute_ad(pool):
    client = _client(ad_pools=[pool], iwa_pools=[])
    check_id = "agentpool_ad_agents_supported_version"
    module = f"prowler.providers.okta.services.agentpool.{check_id}.{check_id}"
    with load_check_with_clients(
        module, {AGENT_CLIENT: {"agent_pool_client": client}}
    ) as loaded:
        return getattr(loaded, check_id)().execute()


def _execute_iwa(pools):
    client = _client(ad_pools=[], iwa_pools=pools)
    check_id = "agentpool_iwa_absent"
    module = f"prowler.providers.okta.services.agentpool.{check_id}.{check_id}"
    with load_check_with_clients(
        module, {AGENT_CLIENT: {"agent_pool_client": client}}
    ) as loaded:
        return getattr(loaded, check_id)().execute()


def _client(ad_pools, iwa_pools):
    client = mock.MagicMock()
    client.resource = OktaResource(id="okta_agent_pools", name="Okta agent pools")
    client.ad_agent_pools = {pool.id: pool for pool in ad_pools}
    client.iwa_agent_pools = {pool.id: pool for pool in iwa_pools}
    return client


def _ad_pool(version="3.20.0", minimum="3.19.0"):
    return OktaAgentPool(
        id="pool-1",
        name="AD Pool",
        type="AD",
        agents=[
            OktaAgent(
                id="agent-1",
                name="agent",
                version=version,
                active=True,
                upgrade_required=False,
            )
        ],
        update_settings={"minimalSupportedVersion": minimum},
    )
