from functools import lru_cache
from pathlib import Path

from django.conf import settings

from api.models import Provider

from ..models import SectoThreat
from .base import RuleContext, RuleSpec, SQLRule

PROVIDER_PACKAGES = {
    Provider.ProviderChoices.M365.value: "m365",
    Provider.ProviderChoices.OKTA.value: "okta",
}


def run_rules_for_provider(
    tenant_id: str,
    provider_id: str,
    provider_type: str,
) -> list[SectoThreat]:
    context = RuleContext(tenant_id=tenant_id, provider_id=provider_id)
    threats: list[SectoThreat] = []
    for spec in _rule_specs(provider_type):
        threats.extend(SQLRule(spec, context).execute())
    return threats


@lru_cache(maxsize=32)
def _rule_specs(provider_type: str) -> tuple[RuleSpec, ...]:
    provider_rules_dir = (
        Path(settings.BASE_DIR)
        / "secto"
        / "rules"
        / "providers"
        / _provider_package(provider_type)
    )
    if not provider_rules_dir.exists():
        return ()

    specs = []
    for metadata_path in sorted(provider_rules_dir.rglob("metadata.json")):
        spec = RuleSpec.from_metadata(metadata_path)
        if spec.provider != provider_type:
            continue
        specs.append(spec)
    return tuple(specs)


def _provider_package(provider_type: str) -> str:
    assert provider_type in PROVIDER_PACKAGES
    return PROVIDER_PACKAGES[provider_type]
