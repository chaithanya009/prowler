from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    active_rule_allows_password_only_access,
    is_broad_policy,
    is_broad_rule,
)


class policy_global_session_no_password_only(Check):
    """Ensure broad global session rules do not allow password-only sign-in."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for policy in policy_client.okta_sign_on_policies.values():
            if policy.status != "ACTIVE" or not is_broad_policy(policy):
                continue

            for rule in policy.rules:
                if rule.status != "ACTIVE" or not is_broad_rule(rule):
                    continue

                report = CheckReportOkta(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_id=f"{policy.id}/{rule.id}",
                    resource_name=f"{policy.name}/{rule.name}",
                )

                if active_rule_allows_password_only_access(rule):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Okta global session policy {policy.name} has broad rule "
                        f"{rule.name} allowing password-only sign-in."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Okta global session policy {policy.name} has broad rule "
                        f"{rule.name} requiring MFA or denying access."
                    )

                findings.append(report)

        return findings
