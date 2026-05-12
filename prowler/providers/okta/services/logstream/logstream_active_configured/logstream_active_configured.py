from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.logstream.logstream_client import logstream_client


class logstream_active_configured(Check):
    """Ensure at least one Okta log stream is active."""

    def execute(self) -> list[CheckReportOkta]:
        active_streams = [
            stream
            for stream in logstream_client.streams.values()
            if stream.status == "ACTIVE"
        ]
        report = CheckReportOkta(
            metadata=self.metadata(), resource=logstream_client.resource
        )

        if active_streams:
            report.status = "PASS"
            report.status_extended = (
                f"Okta has {len(active_streams)} active log stream integrations."
            )
        else:
            report.status = "FAIL"
            report.status_extended = "Okta has no active log stream integrations."

        return [report]
