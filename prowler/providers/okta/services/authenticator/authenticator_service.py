from typing import Any

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.okta.exceptions.exceptions import OktaAPIError
from prowler.providers.okta.lib.service.service import OktaService
from prowler.providers.okta.models import OktaResource


class OktaAuthenticatorMethod(BaseModel):
    """Okta authenticator method."""

    type: str
    status: str
    raw: dict[str, Any] = Field(default_factory=dict)


class OktaAuthenticator(BaseModel):
    """Okta Identity Engine authenticator."""

    id: str
    key: str
    name: str
    status: str
    methods: list[OktaAuthenticatorMethod] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    location: str = "global"


class OktaOrgFactor(BaseModel):
    """Classic Okta org factor."""

    id: str
    factor_type: str
    provider: str
    status: str
    raw: dict[str, Any] = Field(default_factory=dict)
    location: str = "global"


class Authenticator(OktaService):
    """Retrieve Okta authenticators and Classic org factors."""

    def __init__(self, provider):
        super().__init__("Authenticator", provider)
        self.resource = OktaResource(
            id="okta_authenticators", name="Okta authenticators"
        )
        self.authenticators = self._list_authenticators()
        self.org_factors = self._list_org_factors()

    def has_inventory(self) -> bool:
        return bool(self.authenticators or self.org_factors)

    def has_active_method(self, method_type: str) -> bool:
        method_type = method_type.lower()
        for authenticator in self.authenticators.values():
            if authenticator.status != "ACTIVE":
                continue
            for method in authenticator.methods:
                if method.type.lower() == method_type and method.status == "ACTIVE":
                    return True

        for factor in self.org_factors.values():
            if factor.factor_type.lower() == method_type and factor.status == "ACTIVE":
                return True

        return False

    def has_active_authenticator(self, keys: set[str]) -> bool:
        keys = {key.lower() for key in keys}
        for authenticator in self.authenticators.values():
            if authenticator.key.lower() in keys and authenticator.status == "ACTIVE":
                return True

        for factor in self.org_factors.values():
            if factor.id.lower() in keys and factor.status == "ACTIVE":
                return True

        return False

    def _list_authenticators(self) -> dict[str, OktaAuthenticator]:
        logger.info("Authenticator - Listing Okta authenticators...")
        try:
            response_authenticators = self._get_paginated(
                "/api/v1/authenticators", params={"limit": 200}
            )
        except OktaAPIError:
            logger.info("Authenticator - Skipping unavailable authenticators API.")
            return {}

        authenticators = {}
        for authenticator in response_authenticators:
            authenticator_id = authenticator["id"]
            authenticators[authenticator_id] = OktaAuthenticator(
                id=authenticator_id,
                key=authenticator.get("key", authenticator_id),
                name=authenticator.get("name", authenticator_id),
                status=str(authenticator.get("status", "ACTIVE")).upper(),
                methods=self._list_methods(authenticator_id),
                raw=authenticator,
            )

        return authenticators

    def _list_methods(self, authenticator_id: str) -> list[OktaAuthenticatorMethod]:
        try:
            response_methods = self._get_paginated(
                f"/api/v1/authenticators/{authenticator_id}/methods"
            )
        except OktaAPIError:
            return []

        methods = []
        for method in response_methods:
            methods.append(
                OktaAuthenticatorMethod(
                    type=method.get("type", ""),
                    status=str(method.get("status", "ACTIVE")).upper(),
                    raw=method,
                )
            )
        return methods

    def _list_org_factors(self) -> dict[str, OktaOrgFactor]:
        logger.info("Authenticator - Listing Okta org factors...")
        try:
            response_factors = self._get_paginated("/api/v1/org/factors")
        except OktaAPIError:
            logger.info("Authenticator - Skipping unavailable org factors API.")
            return {}

        factors = {}
        for factor in response_factors:
            factor_id = (
                factor.get("id")
                or factor.get("factorType")
                or factor.get("provider")
                or "unknown"
            )
            factors[factor_id] = OktaOrgFactor(
                id=factor_id,
                factor_type=factor.get("factorType", ""),
                provider=factor.get("provider", ""),
                status=str(factor.get("status", "ACTIVE")).upper(),
                raw=factor,
            )
        return factors
