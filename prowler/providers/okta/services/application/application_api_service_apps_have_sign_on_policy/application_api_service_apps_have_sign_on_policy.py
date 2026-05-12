from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.application.application_client import (
    application_client,
)
from prowler.providers.okta.services.policy.policy_client import policy_client


class application_api_service_apps_have_sign_on_policy(Check):
    """Ensure API service apps have explicit app sign-in policy assignments."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []
        mapped_app_ids = _mapped_app_ids()

        for app in application_client.apps.values():
            if app.status != "ACTIVE" or not app.is_api_service_app:
                continue

            report = CheckReportOkta(metadata=self.metadata(), resource=app)
            if app.id in mapped_app_ids:
                report.status = "PASS"
                report.status_extended = (
                    f"Okta API service app {app.label} has an app sign-in policy."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta API service app {app.label} has no explicit app sign-in "
                    "policy."
                )
            findings.append(report)

        return findings


def _mapped_app_ids() -> set[str]:
    mapped = set()
    for policy in policy_client.access_policies.values():
        if policy.status != "ACTIVE":
            continue
        for mapping in policy.mappings:
            if mapping.resource_id:
                mapped.add(mapping.resource_id)
    return mapped
