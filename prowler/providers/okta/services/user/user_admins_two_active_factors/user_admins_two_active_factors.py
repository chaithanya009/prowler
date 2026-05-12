from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.user.user_client import user_client
from prowler.providers.okta.services.user.user_service import (
    MFA_FACTOR_TYPES,
)


class user_admins_two_active_factors(Check):
    """Ensure active Okta admins have at least two active authenticators."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for user in user_client.users.values():
            if user.status != "ACTIVE" or not user.roles:
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=user)
            active_factors = [
                factor
                for factor in user.factors
                if factor.status == "ACTIVE" and factor.factor_type in MFA_FACTOR_TYPES
            ]

            if len(active_factors) >= 2:
                report.status = "PASS"
                report.status_extended = (
                    f"Okta admin {user.login} has at least two active "
                    f"authenticators enrolled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta admin {user.login} has {len(active_factors)} active "
                    f"authenticators enrolled; at least two are recommended."
                )

            findings.append(report)

        return findings
