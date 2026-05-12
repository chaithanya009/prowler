from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.zone.zone_service import Zone

zone_client = Zone(Provider.get_global_provider())
