from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.apitoken.apitoken_service import ApiToken

api_token_client = ApiToken(Provider.get_global_provider())
