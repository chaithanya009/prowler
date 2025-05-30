from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)
from prowler.providers.gcp.services.iam.iam_client import iam_client


class iam_sa_no_administrative_privileges(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for account in iam_client.service_accounts:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=account,
                resource_id=account.email,
                location=iam_client.region,
            )
            report.status = "PASS"
            report.status_extended = (
                f"Account {account.email} has no administrative privileges."
            )
            for binding in cloudresourcemanager_client.bindings:
                if f"serviceAccount:{account.email}" in binding.members and (
                    "admin" in binding.role.lower()
                    or binding.role.lower() in ["roles/editor", "roles/owner"]
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Account {account.email} has administrative privileges with {binding.role}."
            findings.append(report)

        return findings
