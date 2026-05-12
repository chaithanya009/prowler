from urllib.parse import urlparse

from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.application.application_client import (
    application_client,
)


class application_oauth_client_redirect_uris_no_wildcards(Check):
    """Ensure Okta OAuth clients do not use wildcard sign-in redirect hosts."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []
        for client in application_client.clients.values():
            if client.status != "ACTIVE":
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=client)
            wildcard_uris = [
                uri for uri in client.redirect_uris if _has_wildcard_host(uri)
            ]

            if wildcard_uris:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta OAuth client {client.name} has wildcard sign-in "
                    f"redirect URIs: {', '.join(wildcard_uris)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Okta OAuth client {client.name} has no wildcard sign-in "
                    f"redirect URIs."
                )

            findings.append(report)

        return findings


def _has_wildcard_host(uri: str) -> bool:
    hostname = urlparse(uri).hostname or ""
    return "*" in hostname
