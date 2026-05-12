from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.agentpool.agentpool_service import AgentPool

agent_pool_client = AgentPool(Provider.get_global_provider())
