from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)


class authenticator_fastpass_enabled(Check):
    """Ensure Okta FastPass is enabled as a device-bound method."""

    def execute(self) -> list[CheckReportOkta]:
        report = CheckReportOkta(
            metadata=self.metadata(), resource=authenticator_client.resource
        )

        if authenticator_client.has_active_method("signed_nonce"):
            report.status = "PASS"
            report.status_extended = (
                "Okta FastPass signed_nonce authentication is active."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Okta FastPass signed_nonce authentication is not active."
            )

        return [report]
