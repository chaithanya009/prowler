from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.user.user_client import user_client
from prowler.providers.okta.services.user.user_service import (
    MFA_FACTOR_TYPES,
)


class user_mfa_enabled(Check):
    """Ensure active Okta users have an active MFA factor enrolled."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []
        for user in user_client.users.values():
            if user.status != "ACTIVE":
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=user)
            mfa_factors = [
                factor
                for factor in user.factors
                if factor.status == "ACTIVE" and factor.factor_type in MFA_FACTOR_TYPES
            ]

            if mfa_factors:
                report.status = "PASS"
                report.status_extended = (
                    f"Okta user {user.login} has active MFA enrolled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta user {user.login} does not have active MFA enrolled."
                )

            findings.append(report)
        return findings
