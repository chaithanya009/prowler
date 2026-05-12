from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService
from prowler.providers.okta.models import OktaResource


class OktaApiToken(BaseModel):
    """Okta SSWS API token metadata."""

    id: str
    name: str
    user_id: str
    status: str
    network_connection: str
    location: str = "global"


class ApiToken(OktaService):
    """Retrieve Okta SSWS API tokens."""

    def __init__(self, provider):
        super().__init__("ApiToken", provider)
        self.resource = OktaResource(id="okta_api_tokens", name="Okta SSWS API tokens")
        self.tokens = self._list_tokens()

    def _list_tokens(self) -> dict[str, OktaApiToken]:
        logger.info("ApiToken - Listing Okta API tokens...")
        tokens = {}
        response_tokens = self._get_paginated(
            "/api/v1/api-tokens",
            params={"limit": 200},
        )

        for token in response_tokens:
            token_id = token["id"]
            tokens[token_id] = OktaApiToken(
                id=token_id,
                name=token.get("name", token_id),
                user_id=token.get("userId", ""),
                status=str(token.get("status", "ACTIVE")).upper(),
                network_connection=str(
                    token.get("network", {}).get("connection", "ANYWHERE")
                ).upper(),
            )

        return tokens
