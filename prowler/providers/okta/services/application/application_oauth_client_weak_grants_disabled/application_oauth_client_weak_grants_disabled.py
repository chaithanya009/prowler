from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.application.application_client import (
    application_client,
)

WEAK_GRANTS = frozenset({"implicit", "password"})


class application_oauth_client_weak_grants_disabled(Check):
    """Ensure OIDC clients do not allow weak grant types."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for client in application_client.clients.values():
            if client.status != "ACTIVE":
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=client)
            weak_grants = sorted(set(client.grant_types) & WEAK_GRANTS)
            service_grants_invalid = client.application_type == "service" and set(
                client.grant_types
            ) != {"client_credentials"}

            if weak_grants or service_grants_invalid:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta OAuth client {client.name} allows weak or inappropriate "
                    f"grant types: {', '.join(client.grant_types)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Okta OAuth client {client.name} does not allow weak grant "
                    "types."
                )
            findings.append(report)

        return findings
