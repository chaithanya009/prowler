from typing import Any

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService
from prowler.providers.okta.models import OktaResource


class OktaSupportSettings(BaseModel):
    """Okta Support access settings."""

    support: str
    expiration: str | None = None
    case_number: str | None = None
    cases: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    location: str = "global"

    @property
    def has_standing_access(self) -> bool:
        if self.support == "ENABLED" and not self.expiration:
            return True

        for case in self.cases:
            self_assigned = _status(case.get("selfAssigned"))
            impersonation = _dict(case.get("impersonation"))
            if self_assigned == "APPROVED":
                return True
            if _status(impersonation) == "ENABLED" and not impersonation.get(
                "expiration"
            ):
                return True

        return False


class Org(OktaService):
    """Retrieve Okta org-level support settings."""

    def __init__(self, provider):
        super().__init__("Org", provider)
        self.resource = OktaResource(id="okta_org", name="Okta organization")
        self.support_settings = self._get_support_settings()

    def _get_support_settings(self) -> OktaSupportSettings:
        logger.info("Org - Retrieving Okta Support settings...")
        settings = self._get("/api/v1/org/privacy/oktaSupport").json()
        return OktaSupportSettings(
            support=str(settings.get("support", "DISABLED")).upper(),
            expiration=settings.get("expiration"),
            case_number=settings.get("caseNumber"),
            cases=self._list_support_cases(),
            raw=settings,
        )

    def _list_support_cases(self) -> list[dict[str, Any]]:
        response = self._get("/api/v1/org/privacy/oktaSupport/cases").json()
        if isinstance(response, dict):
            return response.get("supportCases", [])
        if isinstance(response, list):
            return response
        return []


def _status(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    return str(value.get("status", "")).upper()


def _dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}
