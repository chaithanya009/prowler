from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.org.org_client import org_client


class org_support_access_not_preapproved(Check):
    """Ensure standing Okta Support access is not pre-approved."""

    def execute(self) -> list[CheckReportOkta]:
        settings = org_client.support_settings
        report = CheckReportOkta(metadata=self.metadata(), resource=org_client.resource)

        if settings.has_standing_access:
            report.status = "FAIL"
            report.status_extended = "Okta Support access is pre-approved or enabled."
        else:
            report.status = "PASS"
            report.status_extended = "Okta Support access is not standing pre-approved."

        return [report]
