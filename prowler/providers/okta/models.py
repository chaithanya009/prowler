from typing import Any, Optional

from pydantic import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class OktaSession(BaseModel):
    """Okta API session information."""

    org_url: str
    api_token: str
    http_session: Any = Field(default=None, exclude=True)


class OktaIdentityInfo(BaseModel):
    """Okta identity information for the token owner."""

    user_id: str
    login: str
    email: Optional[str] = None
    org_url: str


class OktaResource(BaseModel):
    """Generic Okta resource for tenant-level findings."""

    id: str
    name: str
    location: str = "global"


class OktaOutputOptions(ProviderOutputOptions):
    """Customize output filenames for Okta scans."""

    def __init__(self, arguments, bulk_checks_metadata, identity: OktaIdentityInfo):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            account_fragment = identity.login or "okta"
            self.output_filename = (
                f"prowler-output-{account_fragment}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
