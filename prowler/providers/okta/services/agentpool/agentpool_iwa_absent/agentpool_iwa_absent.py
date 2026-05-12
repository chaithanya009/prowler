from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.agentpool.agentpool_client import agent_pool_client


class agentpool_iwa_absent(Check):
    """Ensure no Integrated Windows Authentication agent pools exist."""

    def execute(self) -> list[CheckReportOkta]:
        report = CheckReportOkta(
            metadata=self.metadata(), resource=agent_pool_client.resource
        )

        count = len(agent_pool_client.iwa_agent_pools)
        if count == 0:
            report.status = "PASS"
            report.status_extended = "Okta has no IWA agent pools."
        else:
            report.status = "FAIL"
            report.status_extended = f"Okta has {count} IWA agent pools."

        return [report]
