from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.policy.policy_service import Policy

policy_client = Policy(Provider.get_global_provider())
