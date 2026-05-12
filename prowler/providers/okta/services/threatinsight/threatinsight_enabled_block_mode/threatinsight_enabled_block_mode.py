from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.threatinsight.threatinsight_client import (
    threatinsight_client,
)


class threatinsight_enabled_block_mode(Check):
    """Ensure Okta ThreatInsight is enabled in block mode."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []
        configuration = threatinsight_client.configuration
        report = CheckReportOkta(metadata=self.metadata(), resource=configuration)

        if configuration.action == "block":
            report.status = "PASS"
            report.status_extended = "Okta ThreatInsight is configured in block mode."
        else:
            report.status = "FAIL"
            report.status_extended = f"Okta ThreatInsight action is {configuration.action}; it should be block."

        findings.append(report)
        return findings
