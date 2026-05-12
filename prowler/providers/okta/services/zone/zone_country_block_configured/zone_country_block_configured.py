from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.zone.zone_client import zone_client


class zone_country_block_configured(Check):
    """Ensure an active country-based block zone exists."""

    def execute(self) -> list[CheckReportOkta]:
        report = CheckReportOkta(
            metadata=self.metadata(), resource=zone_client.resource
        )

        if zone_client.has_country_block_zone():
            report.status = "PASS"
            report.status_extended = (
                "Okta has an active country-based network block zone."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Okta does not have an active country-based network block zone."
            )

        return [report]
