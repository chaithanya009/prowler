from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.ratelimit.ratelimit_service import RateLimit

rate_limit_client = RateLimit(Provider.get_global_provider())
