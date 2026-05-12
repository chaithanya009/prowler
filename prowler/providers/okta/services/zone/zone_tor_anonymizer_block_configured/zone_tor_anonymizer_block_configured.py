from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.zone.zone_client import zone_client


class zone_tor_anonymizer_block_configured(Check):
    """Ensure an active block zone exists for Tor anonymizer traffic."""

    def execute(self) -> list[CheckReportOkta]:
        report = CheckReportOkta(
            metadata=self.metadata(), resource=zone_client.resource
        )

        if zone_client.has_tor_block_zone():
            report.status = "PASS"
            report.status_extended = (
                "Okta has an active network block zone for Tor anonymizer traffic."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Okta does not have an active network block zone for Tor anonymizer "
                "traffic."
            )

        return [report]
