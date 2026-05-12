from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    password_min_length_at_least,
)


class policy_password_min_length_strong(Check):
    """Ensure active password policies require at least eight characters."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for policy in policy_client.password_policies.values():
            if policy.status != "ACTIVE":
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=policy)
            if password_min_length_at_least(policy, 8):
                report.status = "PASS"
                report.status_extended = (
                    f"Okta password policy {policy.name} requires at least 8 "
                    "characters."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta password policy {policy.name} does not require at least "
                    "8 characters."
                )
            findings.append(report)

        return findings
