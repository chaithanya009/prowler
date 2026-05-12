from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.application.application_client import (
    application_client,
)


class application_assignments_use_groups(Check):
    """Ensure apps are assigned through groups instead of directly to users."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for app in application_client.apps.values():
            if app.status != "ACTIVE":
                continue
            if app.is_okta_managed:
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=app)
            if not app.users and app.groups:
                report.status = "PASS"
                report.status_extended = (
                    f"Okta app {app.label} is assigned through groups and has no "
                    "direct user assignments."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta app {app.label} has direct user assignments or no group "
                    "assignment."
                )
            findings.append(report)

        return findings
