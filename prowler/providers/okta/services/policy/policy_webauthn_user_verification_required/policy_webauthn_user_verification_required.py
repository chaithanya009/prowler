from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    active_rule_allows_webauthn,
    active_rule_requires_webauthn_user_verification,
    is_broad_rule,
)


class policy_webauthn_user_verification_required(Check):
    """Ensure WebAuthn user verification is required where WebAuthn is used."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for policy in policy_client.access_policies.values():
            if policy.status != "ACTIVE":
                continue
            for rule in policy.rules:
                if not is_broad_rule(rule) or not active_rule_allows_webauthn(rule):
                    continue

                report = CheckReportOkta(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_id=f"{policy.id}/{rule.id}",
                    resource_name=f"{policy.name}/{rule.name}",
                )
                if active_rule_requires_webauthn_user_verification(rule):
                    report.status = "PASS"
                    report.status_extended = (
                        f"Okta policy rule {rule.name} requires WebAuthn user "
                        "verification."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Okta policy rule {rule.name} allows WebAuthn without "
                        "requiring user verification."
                    )
                findings.append(report)

        return findings
