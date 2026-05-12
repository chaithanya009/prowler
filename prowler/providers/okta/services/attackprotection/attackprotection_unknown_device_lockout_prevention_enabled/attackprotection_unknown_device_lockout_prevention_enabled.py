from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.attackprotection.attackprotection_client import (
    attack_protection_client,
)


class attackprotection_unknown_device_lockout_prevention_enabled(Check):
    """Ensure brute-force lockout protection for unknown devices is enabled."""

    def execute(self) -> list[CheckReportOkta]:
        settings = attack_protection_client.user_lockout_settings
        report = CheckReportOkta(metadata=self.metadata(), resource=settings)

        if settings.prevent_brute_force_lockout_from_unknown_devices:
            report.status = "PASS"
            report.status_extended = (
                "Okta prevents brute-force lockout from unknown devices."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Okta does not prevent brute-force lockout from unknown devices."
            )

        return [report]
