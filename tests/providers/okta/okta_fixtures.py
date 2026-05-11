from unittest.mock import MagicMock

from prowler.providers.okta.models import OktaIdentityInfo, OktaSession

ORG_URL = "https://example.okta.com"
API_TOKEN = "test-okta-api-token"
USER_ID = "00u1"
USER_LOGIN = "alice@example.com"
USER_EMAIL = "alice@example.com"


def set_mocked_okta_provider(
    org_url: str = ORG_URL,
    api_token: str = API_TOKEN,
    identity: OktaIdentityInfo = None,
    audit_config: dict = None,
):
    provider = MagicMock()
    provider.type = "okta"
    provider.session = OktaSession(
        org_url=org_url,
        api_token=api_token,
        http_session=MagicMock(),
    )
    provider.identity = identity or OktaIdentityInfo(
        user_id=USER_ID,
        login=USER_LOGIN,
        email=USER_EMAIL,
        org_url=org_url,
    )
    provider.audit_config = audit_config or {"max_retries": 3}
    provider.fixer_config = {}
    return provider
