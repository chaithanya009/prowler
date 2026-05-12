from typing import Any

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.okta.exceptions.exceptions import OktaAPIError
from prowler.providers.okta.lib.service.service import OktaService
from prowler.providers.okta.models import OktaResource


class OktaOAuthClient(BaseModel):
    """Okta OAuth or OIDC client application."""

    id: str
    name: str
    status: str
    application_type: str
    grant_types: list[str] = Field(default_factory=list)
    redirect_uris: list[str] = Field(default_factory=list)
    location: str = "global"


class OktaApplicationFeature(BaseModel):
    """Okta application feature settings."""

    id: str
    status: str
    raw: dict[str, Any] = Field(default_factory=dict)


class OktaApplication(BaseModel):
    """Okta application with assignments and provisioning features."""

    id: str
    name: str
    label: str
    status: str
    sign_on_mode: str
    features: list[str] = Field(default_factory=list)
    settings: dict[str, Any] = Field(default_factory=dict)
    users: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    user_provisioning: OktaApplicationFeature | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    location: str = "global"

    @property
    def is_api_service_app(self) -> bool:
        oauth_client = self.settings.get("oauthClient", {})
        return str(oauth_client.get("application_type", "")).lower() == "service"

    @property
    def is_okta_managed(self) -> bool:
        if self.name.startswith("okta_"):
            return True
        if self.name in {"saasure", "flow"}:
            return True
        return str(self.raw.get("orn", "")).startswith("orn:okta:")


class OktaAdminConsoleSettings(BaseModel):
    """Okta first-party Admin Console session settings."""

    id: str = "okta_admin_console_settings"
    name: str = "Okta Admin Console settings"
    session_max_lifetime_minutes: int | None = None
    session_idle_timeout_minutes: int | None = None
    location: str = "global"


class Application(OktaService):
    """Retrieve Okta OAuth clients and applications."""

    def __init__(self, provider):
        super().__init__("Application", provider)
        self.resource = OktaResource(id="okta_applications", name="Okta applications")
        self.clients = self._list_clients()
        self.apps = self._list_apps()
        self.admin_console_settings = self._get_admin_console_settings()

    def _list_clients(self) -> dict[str, OktaOAuthClient]:
        logger.info("Application - Listing Okta OAuth clients...")
        clients = {}
        response_clients = self._get_paginated(
            "/oauth2/v1/clients",
            params={"limit": 200},
        )

        for client in response_clients:
            client_id = client["client_id"]
            clients[client_id] = OktaOAuthClient(
                id=client_id,
                name=client.get("client_name", client_id),
                status=str(client.get("status", "ACTIVE")).upper(),
                application_type=client.get("application_type", ""),
                grant_types=client.get("grant_types", []),
                redirect_uris=client.get("redirect_uris", []),
            )

        return clients

    def _list_apps(self) -> dict[str, OktaApplication]:
        logger.info("Application - Listing Okta applications...")
        apps = {}
        response_apps = self._get_paginated(
            "/api/v1/apps",
            params={"limit": 200},
        )

        for app in response_apps:
            app_id = app["id"]
            apps[app_id] = OktaApplication(
                id=app_id,
                name=app.get("name", app_id),
                label=app.get("label", app_id),
                status=str(app.get("status", "ACTIVE")).upper(),
                sign_on_mode=app.get("signOnMode", ""),
                features=app.get("features", []),
                settings=app.get("settings", {}),
                users=self._list_app_users(app_id),
                groups=self._list_app_groups(app_id),
                user_provisioning=self._get_user_provisioning(app_id),
                raw=app,
            )

        return apps

    def _list_app_users(self, app_id: str) -> list[str]:
        response_users = self._get_paginated(
            f"/api/v1/apps/{app_id}/users", params={"limit": 200}
        )
        return [user.get("id", "") for user in response_users if user.get("id")]

    def _list_app_groups(self, app_id: str) -> list[str]:
        response_groups = self._get_paginated(
            f"/api/v1/apps/{app_id}/groups", params={"limit": 200}
        )
        return [group.get("id", "") for group in response_groups if group.get("id")]

    def _get_user_provisioning(self, app_id: str) -> OktaApplicationFeature | None:
        try:
            response = self._get(f"/api/v1/apps/{app_id}/features/USER_PROVISIONING")
        except OktaAPIError:
            return None

        feature = response.json()
        return OktaApplicationFeature(
            id="USER_PROVISIONING",
            status=str(feature.get("status", "")).upper(),
            raw=feature,
        )

    def _get_admin_console_settings(self) -> OktaAdminConsoleSettings:
        try:
            response = self._get("/api/v1/first-party-app-settings/admin-console")
        except OktaAPIError:
            return OktaAdminConsoleSettings()

        settings = response.json()
        return OktaAdminConsoleSettings(
            session_max_lifetime_minutes=settings.get("sessionMaxLifetimeMinutes"),
            session_idle_timeout_minutes=settings.get("sessionIdleTimeoutMinutes"),
        )
