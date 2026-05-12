from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    active_rule_requires_managed_device,
    is_admin_console_policy,
    is_broad_rule,
)


class policy_admin_console_managed_device_required(Check):
    """Ensure the Admin Console policy requires managed devices."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for policy in policy_client.access_policies.values():
            if policy.status != "ACTIVE" or not is_admin_console_policy(policy):
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
                if active_rule_requires_managed_device(rule):
                    report.status = "PASS"
                    report.status_extended = (
                        f"Okta Admin Console policy rule {rule.name} requires a "
                        "managed device."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Okta Admin Console policy rule {rule.name} does not "
                        "require a managed device."
                    )
                findings.append(report)

        return findings
