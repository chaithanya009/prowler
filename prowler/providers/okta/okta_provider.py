import os

import requests
from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.okta.exceptions.exceptions import (
    OktaAuthenticationError,
    OktaCredentialsError,
    OktaIdentityError,
    OktaRateLimitError,
    OktaSessionError,
)
from prowler.providers.okta.lib.mutelist.mutelist import OktaMutelist
from prowler.providers.okta.models import OktaIdentityInfo, OktaSession


class OktaProvider(Provider):
    """Okta provider."""

    _type: str = "okta"
    _session: OktaSession
    _identity: OktaIdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: OktaMutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        api_token: str = None,
        org_url: str = None,
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        logger.info("Instantiating Okta provider...")

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._session = OktaProvider.setup_session(
            api_token=api_token,
            org_url=org_url,
        )
        self._identity = OktaProvider.setup_identity(self._session)
        self._fixer_config = fixer_config

        if mutelist_content:
            self._mutelist = OktaMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = OktaMutelist(mutelist_path=mutelist_path)

        Provider.set_global_provider(self)

    @property
    def type(self):
        return self._type

    @property
    def session(self):
        return self._session

    @property
    def identity(self):
        return self._identity

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self):
        return self._mutelist

    @staticmethod
    def setup_session(api_token: str = None, org_url: str = None) -> OktaSession:
        token = api_token or os.environ.get("OKTA_API_TOKEN", "")
        url = (org_url or os.environ.get("OKTA_ORG_URL", "")).rstrip("/")

        if not token:
            raise OktaCredentialsError(
                file=os.path.basename(__file__),
                message="Okta API token not found. Set OKTA_API_TOKEN.",
            )
        if not url:
            raise OktaCredentialsError(
                file=os.path.basename(__file__),
                message="Okta org URL not found. Set OKTA_ORG_URL.",
            )

        try:
            http_session = requests.Session()
            http_session.headers.update(
                {
                    "Authorization": f"SSWS {token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }
            )
            return OktaSession(
                org_url=url,
                api_token=token,
                http_session=http_session,
            )
        except Exception as error:
            raise OktaSessionError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    @staticmethod
    def setup_identity(session: OktaSession) -> OktaIdentityInfo:
        try:
            response = session.http_session.get(
                f"{session.org_url}/api/v1/users/me",
                timeout=30,
            )
            response.raise_for_status()
            user = response.json()
            profile = user["profile"]
            return OktaIdentityInfo(
                user_id=user["id"],
                login=profile["login"],
                email=profile.get("email"),
                org_url=session.org_url,
            )
        except Exception as error:
            raise OktaIdentityError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    @staticmethod
    def validate_credentials(session: OktaSession) -> None:
        try:
            response = session.http_session.get(
                f"{session.org_url}/api/v1/users/me",
                timeout=30,
            )
            if response.status_code in (401, 403):
                raise OktaAuthenticationError(
                    file=os.path.basename(__file__),
                    message="Invalid Okta API token or insufficient permissions.",
                )
            if response.status_code == 429:
                raise OktaRateLimitError(file=os.path.basename(__file__))
            response.raise_for_status()
        except (OktaAuthenticationError, OktaRateLimitError):
            raise
        except requests.exceptions.RequestException as error:
            raise OktaAuthenticationError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    def print_credentials(self) -> None:
        report_title = (
            f"{Style.BRIGHT}Using the Okta credentials below:{Style.RESET_ALL}"
        )
        report_lines = [
            f"Authentication: {Fore.YELLOW}API Token{Style.RESET_ALL}",
            f"Org URL: {Fore.YELLOW}{self.identity.org_url}{Style.RESET_ALL}",
            f"Login: {Fore.YELLOW}{self.identity.login}{Style.RESET_ALL}",
        ]
        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        api_token: str = None,
        org_url: str = None,
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> Connection:
        try:
            if provider_id and not org_url:
                org_url = provider_id
            session = OktaProvider.setup_session(
                api_token=api_token,
                org_url=org_url,
            )
            OktaProvider.validate_credentials(session)
            return Connection(is_connected=True)
        except Exception as error:
            if raise_on_exception:
                raise
            return Connection(is_connected=False, error=error)
