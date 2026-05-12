from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.agentpool.agentpool_client import agent_pool_client


class agentpool_ad_agents_supported_version(Check):
    """Ensure AD agent pools have update settings and supported versions."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []

        for pool in agent_pool_client.ad_agent_pools.values():
            report = CheckReportOkta(metadata=self.metadata(), resource=pool)
            if (
                pool.has_update_settings
                and not pool.below_minimum_supported_version
                and not pool.has_upgrade_required_agent
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Okta AD agent pool {pool.name} has update settings and no "
                    "agent below the minimum supported version."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta AD agent pool {pool.name} lacks update settings or has "
                    "an agent below the minimum supported version."
                )
            findings.append(report)

        return findings
