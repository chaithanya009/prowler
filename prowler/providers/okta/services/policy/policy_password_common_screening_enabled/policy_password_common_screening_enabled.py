from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    password_common_screening_enabled,
)


class policy_password_common_screening_enabled(Check):
    """Ensure common-password screening is enabled."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for policy in policy_client.password_policies.values():
            if policy.status != "ACTIVE":
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=policy)
            if password_common_screening_enabled(policy):
                report.status = "PASS"
                report.status_extended = (
                    f"Okta password policy {policy.name} screens common passwords."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta password policy {policy.name} does not screen common "
                    "passwords."
                )
            findings.append(report)

        return findings
