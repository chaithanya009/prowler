from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    is_broad_policy,
    policy_has_known_enrollment_settings,
    policy_has_required_enrollment,
)


class policy_authenticator_enrollment_requires_factor(Check):
    """Ensure broad authenticator enrollment policies require a factor."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for policy in policy_client.mfa_enroll_policies.values():
            if policy.status != "ACTIVE" or not is_broad_policy(policy):
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=policy)

            if policy_has_required_enrollment(policy):
                report.status = "PASS"
                report.status_extended = (
                    f"Okta authenticator enrollment policy {policy.name} requires "
                    f"at least one factor or authenticator."
                )
            elif not policy_has_known_enrollment_settings(policy):
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta authenticator enrollment policy {policy.name} uses an "
                    f"unknown enrollment settings schema."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta authenticator enrollment policy {policy.name} does not "
                    f"require any factor or authenticator."
                )

            findings.append(report)

        return findings
