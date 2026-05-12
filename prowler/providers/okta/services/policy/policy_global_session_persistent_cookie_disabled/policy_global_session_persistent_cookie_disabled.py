from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    active_rule_uses_persistent_cookie,
    is_broad_policy,
    is_broad_rule,
)


class policy_global_session_persistent_cookie_disabled(Check):
    """Ensure persistent cookies are disabled for broad global session access."""

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
                if active_rule_uses_persistent_cookie(rule):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Okta global session rule {rule.name} allows persistent "
                        "cookies."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Okta global session rule {rule.name} does not allow "
                        "persistent cookies."
                    )
                findings.append(report)

        return findings
