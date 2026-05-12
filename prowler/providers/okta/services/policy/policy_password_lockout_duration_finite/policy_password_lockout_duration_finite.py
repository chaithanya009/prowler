from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    password_lockout_duration_finite,
)


class policy_password_lockout_duration_finite(Check):
    """Ensure password lockout duration is finite."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for policy in policy_client.password_policies.values():
            if policy.status != "ACTIVE":
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=policy)
            if password_lockout_duration_finite(policy):
                report.status = "PASS"
                report.status_extended = (
                    f"Okta password policy {policy.name} has finite auto-unlock."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta password policy {policy.name} has indefinite or missing "
                    "auto-unlock."
                )
            findings.append(report)

        return findings
