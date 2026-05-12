from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.attackprotection.attackprotection_service import (
    AttackProtection,
)

attack_protection_client = AttackProtection(Provider.get_global_provider())
