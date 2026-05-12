from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    is_broad_policy,
    policy_allows_authenticator,
)


class authenticator_passkey_enabled(Check):
    """Ensure Passkey (FIDO2 WebAuthn) is enabled for workforce users."""

    def execute(self) -> list[CheckReportOkta]:
        report = CheckReportOkta(
            metadata=self.metadata(), resource=authenticator_client.resource
        )

        if not authenticator_client.has_active_authenticator({"webauthn"}):
            report.status = "FAIL"
            report.status_extended = "Okta Passkey (FIDO2 WebAuthn) is not active."
            return [report]

        for policy in policy_client.mfa_enroll_policies.values():
            if policy.status != "ACTIVE" or not is_broad_policy(policy):
                continue
            if policy_allows_authenticator(policy, "webauthn"):
                report.status = "PASS"
                report.status_extended = (
                    "Okta Passkey (FIDO2 WebAuthn) is active and allowed by a "
                    "broad authenticator enrollment policy."
                )
                return [report]

        report.status = "FAIL"
        report.status_extended = (
            "Okta Passkey (FIDO2 WebAuthn) is active but not allowed by a broad "
            "authenticator enrollment policy."
        )
        return [report]
