import time
from urllib.parse import urljoin

import requests

from prowler.lib.logger import logger
from prowler.providers.okta.exceptions.exceptions import (
    OktaAPIError,
    OktaRateLimitError,
)


class OktaService:
    """Base class for Okta services."""

    def __init__(self, service: str, provider):
        self.provider = provider
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower()
        self._http_session = provider.session.http_session
        self._org_url = provider.session.org_url

    def _get(self, path: str, params: dict = None):
        return self._get_url(urljoin(f"{self._org_url}/", path.lstrip("/")), params)

    def _get_url(self, url: str, params: dict = None):
        max_retries = self.audit_config.get("max_retries", 3)
        for attempt in range(max_retries + 1):
            try:
                if params is None:
                    response = self._http_session.get(url, timeout=30)
                else:
                    response = self._http_session.get(url, params=params, timeout=30)
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 5))
                    if attempt < max_retries:
                        logger.warning(
                            f"{self.service} - Rate limited, retrying after {retry_after}s."
                        )
                        time.sleep(retry_after)
                        continue
                    raise OktaRateLimitError(file=__file__)
                response.raise_for_status()
                return response
            except OktaRateLimitError:
                raise
            except requests.exceptions.RequestException as error:
                if attempt < max_retries:
                    time.sleep(2**attempt)
                    continue
                raise OktaAPIError(file=__file__, original_exception=error)

        raise OktaAPIError(file=__file__, message=f"Request failed for {url}.")
