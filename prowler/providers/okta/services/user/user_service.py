from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService
from prowler.providers.okta.models import OktaResource

MFA_FACTOR_TYPES = frozenset(
    {
        "call",
        "email",
        "push",
        "signed_nonce",
        "sms",
        "token",
        "token:hardware",
        "token:hotp",
        "token:software:totp",
        "u2f",
        "webauthn",
    }
)


class OktaFactor(BaseModel):
    """Okta user factor."""

    id: str
    factor_type: str
    provider: str
    status: str


class OktaUser(BaseModel):
    """Okta user with enrolled factors."""

    id: str
    login: str
    email: str | None = None
    status: str
    factors: list[OktaFactor] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)


class User(OktaService):
    """Retrieve Okta users and enrolled factors."""

    def __init__(self, provider):
        super().__init__("User", provider)
        self.resource = OktaResource(id="okta_admin_roles", name="Okta admin roles")
        self.users: dict[str, OktaUser] = self._list_users()

    def _list_users(self) -> dict[str, OktaUser]:
        logger.info("User - Listing Okta users...")
        users = {}
        response_users = self._get_paginated(
            "/api/v1/users",
            params={"limit": 200, "filter": 'status eq "ACTIVE"'},
        )

        for user in response_users:
            user_id = user["id"]
            profile = user["profile"]
            users[user_id] = OktaUser(
                id=user_id,
                login=profile["login"],
                email=profile.get("email"),
                status=str(user["status"]).upper(),
            )

        for user in users.values():
            user.factors = self._list_factors(user.id)
            user.roles = self._list_roles(user.id)

        return users

    def _list_factors(self, user_id: str) -> list[OktaFactor]:
        response = self._get(f"/api/v1/users/{user_id}/factors")
        factors = []
        for factor in response.json():
            factors.append(
                OktaFactor(
                    id=factor["id"],
                    factor_type=factor["factorType"],
                    provider=factor["provider"],
                    status=factor["status"],
                )
            )
        return factors

    def _list_roles(self, user_id: str) -> list[str]:
        roles = []
        response_roles = self._get_paginated(f"/api/v1/users/{user_id}/roles")

        for role in response_roles:
            role_type = role.get("type", "")
            if role_type:
                roles.append(str(role_type).upper())

        return roles
