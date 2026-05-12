from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.apitoken.apitoken_client import api_token_client


class apitoken_network_restricted(Check):
    """Ensure active Okta SSWS API tokens are network-restricted."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []
        active_tokens = [
            token
            for token in api_token_client.tokens.values()
            if token.status == "ACTIVE"
        ]

        if not active_tokens:
            report = CheckReportOkta(
                metadata=self.metadata(),
                resource=api_token_client.resource,
            )
            report.status = "PASS"
            report.status_extended = "Okta has no active SSWS API tokens."
            return [report]

        for token in active_tokens:
            report = CheckReportOkta(metadata=self.metadata(), resource=token)

            if token.network_connection != "ANYWHERE":
                report.status = "PASS"
                report.status_extended = (
                    f"Okta SSWS API token {token.name} is restricted to "
                    f"{token.network_connection}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta SSWS API token {token.name} can be used from anywhere."
                )

            findings.append(report)

        return findings
