from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    active_rule_has_finite_session_lifetime,
    is_broad_policy,
    is_broad_rule,
)


class policy_global_session_lifetime_bounded(Check):
    """Ensure global session lifetime is finite and bounded."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []
        threshold = policy_client.audit_config.get(
            "max_global_session_lifetime_minutes", 720
        )

        for policy in policy_client.okta_sign_on_policies.values():
            if policy.status != "ACTIVE" or not is_broad_policy(policy):
                continue
            for rule in policy.rules:
                if rule.status != "ACTIVE" or not is_broad_rule(rule):
                    continue
                report = _rule_report(self, policy, rule)
                if active_rule_has_finite_session_lifetime(rule, threshold):
                    report.status = "PASS"
                    report.status_extended = (
                        f"Okta global session rule {rule.name} has a finite "
                        f"session lifetime within {threshold} minutes."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Okta global session rule {rule.name} has no finite "
                        f"session lifetime within {threshold} minutes."
                    )
                findings.append(report)

        return findings


def _rule_report(check, policy, rule):
    return CheckReportOkta(
        metadata=check.metadata(),
        resource=policy,
        resource_id=f"{policy.id}/{rule.id}",
        resource_name=f"{policy.name}/{rule.name}",
    )
