from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    active_rule_has_bounded_mfa_lifetime,
    active_rule_has_mfa_lifetime_setting,
    is_broad_policy,
    is_broad_rule,
)


class policy_global_session_mfa_lifetime_bounded(Check):
    """Ensure MFA re-prompt interval is not effectively unlimited."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []
        threshold = policy_client.audit_config.get("max_mfa_lifetime_minutes", 720)

        for policy in policy_client.okta_sign_on_policies.values():
            if policy.status != "ACTIVE" or not is_broad_policy(policy):
                continue
            for rule in policy.rules:
                if rule.status != "ACTIVE" or not is_broad_rule(rule):
                    continue
                if not active_rule_has_mfa_lifetime_setting(rule):
                    continue
                report = CheckReportOkta(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_id=f"{policy.id}/{rule.id}",
                    resource_name=f"{policy.name}/{rule.name}",
                )
                if active_rule_has_bounded_mfa_lifetime(rule, threshold):
                    report.status = "PASS"
                    report.status_extended = (
                        f"Okta global session rule {rule.name} has a bounded "
                        f"MFA re-prompt interval within {threshold} minutes."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Okta global session rule {rule.name} does not have a "
                        f"bounded MFA re-prompt interval within {threshold} minutes."
                    )
                findings.append(report)

        return findings
