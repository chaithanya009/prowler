from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.application.application_client import (
    application_client,
)


class application_admin_console_session_lifetime_bounded(Check):
    """Ensure Admin Console session lifetime and idle timeout are bounded."""

    def execute(self) -> list[CheckReportOkta]:
        settings = application_client.admin_console_settings
        max_lifetime = application_client.audit_config.get(
            "max_admin_console_session_lifetime_minutes", 720
        )
        max_idle = application_client.audit_config.get(
            "max_admin_console_idle_minutes", 15
        )
        report = CheckReportOkta(metadata=self.metadata(), resource=settings)

        lifetime_ok = _bounded(settings.session_max_lifetime_minutes, max_lifetime)
        idle_ok = _bounded(settings.session_idle_timeout_minutes, max_idle)
        if lifetime_ok and idle_ok:
            report.status = "PASS"
            report.status_extended = (
                "Okta Admin Console session lifetime and idle timeout are bounded."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Okta Admin Console session lifetime or idle timeout is missing or "
                "too long."
            )

        return [report]


def _bounded(value: int | None, maximum: int) -> bool:
    return value is not None and 0 < value <= maximum
