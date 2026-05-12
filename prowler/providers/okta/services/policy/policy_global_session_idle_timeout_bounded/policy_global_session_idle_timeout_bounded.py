from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    active_rule_has_finite_idle_timeout,
    is_broad_policy,
    is_broad_rule,
)


class policy_global_session_idle_timeout_bounded(Check):
    """Ensure global session idle timeout is finite and bounded."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []
        threshold = policy_client.audit_config.get(
            "max_global_session_idle_minutes", 120
        )

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
                if active_rule_has_finite_idle_timeout(rule, threshold):
                    report.status = "PASS"
                    report.status_extended = (
                        f"Okta global session rule {rule.name} has a finite "
                        f"idle timeout within {threshold} minutes."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Okta global session rule {rule.name} has no finite "
                        f"idle timeout within {threshold} minutes."
                    )
                findings.append(report)

        return findings
