from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.ratelimit.ratelimit_client import rate_limit_client


class ratelimit_per_client_enforced(Check):
    """Ensure per-client rate limiting is enforced."""

    def execute(self) -> list[CheckReportOkta]:
        settings = rate_limit_client.per_client_settings
        report = CheckReportOkta(metadata=self.metadata(), resource=settings)

        if settings.enforced:
            report.status = "PASS"
            report.status_extended = "Okta per-client rate limiting is enforced."
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Okta per-client rate limiting is disabled or only in preview."
            )

        return [report]
