from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.application.application_client import (
    application_client,
)


class application_provisioning_deactivation_enabled(Check):
    """Ensure provisioned apps push user deactivation downstream."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for app in application_client.apps.values():
            feature = app.user_provisioning
            if app.status != "ACTIVE" or feature is None:
                continue
            if feature.status and feature.status != "ENABLED":
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=app)
            if _deactivation_enabled(feature.raw):
                report.status = "PASS"
                report.status_extended = (
                    f"Okta app {app.label} pushes user deactivation downstream."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta app {app.label} does not push user deactivation "
                    "downstream."
                )
            findings.append(report)

        return findings


def _deactivation_enabled(feature: dict) -> bool:
    update = feature.get("update", {})
    lifecycle = update.get("lifecycleDeactivate", {})
    if str(lifecycle.get("status", "")).upper() == "ENABLED":
        return True

    push = feature.get("PUSH_USER_DEACTIVATION", {})
    return str(push.get("status", "")).upper() == "ENABLED"
