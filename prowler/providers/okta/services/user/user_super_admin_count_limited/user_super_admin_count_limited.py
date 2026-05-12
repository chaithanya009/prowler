from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.user.user_client import user_client


class user_super_admin_count_limited(Check):
    """Ensure the active Okta Super Admin population is small."""

    def execute(self) -> list[CheckReportOkta]:
        threshold = user_client.audit_config.get("max_super_admins", 3)
        super_admins = [
            user
            for user in user_client.users.values()
            if user.status == "ACTIVE" and "SUPER_ADMIN" in user.roles
        ]
        report = CheckReportOkta(
            metadata=self.metadata(), resource=user_client.resource
        )

        if len(super_admins) <= threshold:
            report.status = "PASS"
            report.status_extended = (
                f"Okta has {len(super_admins)} active Super Admins, "
                f"within the threshold of {threshold}."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                f"Okta has {len(super_admins)} active Super Admins, "
                f"which exceeds the threshold of {threshold}."
            )

        return [report]
