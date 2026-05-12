from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)


class authenticator_voice_disabled(Check):
    """Ensure voice-call MFA is disabled org-wide."""

    def execute(self) -> list[CheckReportOkta]:
        report = CheckReportOkta(
            metadata=self.metadata(), resource=authenticator_client.resource
        )

        if authenticator_client.has_active_method(
            "voice"
        ) or authenticator_client.has_active_method("call"):
            report.status = "FAIL"
            report.status_extended = "Okta voice-call MFA is active."
        else:
            report.status = "PASS"
            report.status_extended = "Okta voice-call MFA is not active."

        return [report]
