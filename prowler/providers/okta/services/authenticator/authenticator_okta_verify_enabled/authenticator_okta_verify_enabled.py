from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)


class authenticator_okta_verify_enabled(Check):
    """Ensure Okta Verify is enabled for users."""

    def execute(self) -> list[CheckReportOkta]:
        report = CheckReportOkta(
            metadata=self.metadata(), resource=authenticator_client.resource
        )

        enabled = authenticator_client.has_active_authenticator(
            {"okta_verify", "okta_otp"}
        )
        enabled = enabled or authenticator_client.has_active_method("push")
        enabled = enabled or authenticator_client.has_active_method("totp")
        enabled = enabled or authenticator_client.has_active_method("signed_nonce")

        if enabled:
            report.status = "PASS"
            report.status_extended = "Okta Verify is active."
        else:
            report.status = "FAIL"
            report.status_extended = "Okta Verify is not active."

        return [report]
