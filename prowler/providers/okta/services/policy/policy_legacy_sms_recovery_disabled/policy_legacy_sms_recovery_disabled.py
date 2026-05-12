from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    legacy_sms_recovery_enabled,
)


class policy_legacy_sms_recovery_disabled(Check):
    """Ensure legacy SMS self-service recovery is disabled."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for policy in policy_client.password_policies.values():
            if policy.status != "ACTIVE":
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=policy)
            if legacy_sms_recovery_enabled(policy):
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta password policy {policy.name} allows legacy SMS recovery."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Okta password policy {policy.name} does not allow legacy SMS "
                    "recovery."
                )
            findings.append(report)

        return findings
