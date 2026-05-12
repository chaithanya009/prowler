from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.org.org_service import Org

org_client = Org(Provider.get_global_provider())
