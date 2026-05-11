from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService


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


class User(OktaService):
    """Retrieve Okta users and enrolled factors."""

    def __init__(self, provider):
        super().__init__("User", provider)
        self.users: dict[str, OktaUser] = self._list_users()

    def _list_users(self) -> dict[str, OktaUser]:
        logger.info("User - Listing Okta users...")
        users = {}
        next_url = None

        while True:
            if next_url:
                response = self._get_url(next_url)
            else:
                response = self._get("/api/v1/users", params={"limit": 200})

            for user in response.json():
                user_id = user["id"]
                profile = user["profile"]
                users[user_id] = OktaUser(
                    id=user_id,
                    login=profile["login"],
                    email=profile.get("email"),
                    status=user["status"],
                )

            next_url = self._next_link(response.headers.get("Link", ""))
            if not next_url:
                break

        for user in users.values():
            user.factors = self._list_factors(user.id)

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

    @staticmethod
    def _next_link(link_header: str) -> str | None:
        for link in link_header.split(","):
            if 'rel="next"' in link:
                return link.split(";", 1)[0].strip()[1:-1]
        return None
