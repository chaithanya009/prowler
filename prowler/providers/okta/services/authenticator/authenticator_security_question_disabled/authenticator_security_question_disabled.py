from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)


class authenticator_security_question_disabled(Check):
    """Ensure Security Question is disabled org-wide."""

    def execute(self) -> list[CheckReportOkta]:
        report = CheckReportOkta(
            metadata=self.metadata(), resource=authenticator_client.resource
        )

        enabled = authenticator_client.has_active_method(
            "security_question"
        ) or authenticator_client.has_active_method("question")
        enabled = enabled or authenticator_client.has_active_authenticator(
            {"security_question", "okta_question"}
        )

        if enabled:
            report.status = "FAIL"
            report.status_extended = "Okta Security Question is active."
        else:
            report.status = "PASS"
            report.status_extended = "Okta Security Question is not active."

        return [report]
