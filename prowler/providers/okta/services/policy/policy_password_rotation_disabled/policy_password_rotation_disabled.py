from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    password_rotation_disabled,
)


class policy_password_rotation_disabled(Check):
    """Ensure forced password rotation is disabled for general users."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for policy in policy_client.password_policies.values():
            if policy.status != "ACTIVE":
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=policy)
            if password_rotation_disabled(policy):
                report.status = "PASS"
                report.status_extended = (
                    f"Okta password policy {policy.name} does not force periodic "
                    "password rotation."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta password policy {policy.name} forces periodic password "
                    "rotation."
                )
            findings.append(report)

        return findings
