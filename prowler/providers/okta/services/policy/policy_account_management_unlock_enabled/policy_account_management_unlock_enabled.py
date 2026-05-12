from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.models import OktaResource
from prowler.providers.okta.services.policy.policy_client import policy_client
from prowler.providers.okta.services.policy.policy_service import (
    is_account_management_policy,
    legacy_unlock_enabled,
)


class policy_account_management_unlock_enabled(Check):
    """Ensure account unlock is governed by Okta account management policy."""

    def execute(self) -> list[CheckReportOkta]:
        report = CheckReportOkta(
            metadata=self.metadata(),
            resource_id="okta_account_management_policy",
            resource_name="Okta account management policy",
            resource=_resource(),
        )

        if _has_active_account_management_policy():
            report.status = "PASS"
            report.status_extended = (
                "Okta account management policy governs account unlock."
            )
            return [report]

        if _has_legacy_unlock():
            report.status = "FAIL"
            report.status_extended = (
                "Okta account unlock relies on legacy unlock instead of account "
                "management policy."
            )
            return [report]

        report.status = "FAIL"
        report.status_extended = "Okta account management policy is not active."
        return [report]


def _has_active_account_management_policy() -> bool:
    for policy in policy_client.access_policies.values():
        if (
            policy.status == "ACTIVE"
            and is_account_management_policy(policy)
            and any(rule.status == "ACTIVE" for rule in policy.rules)
        ):
            return True
    return False


def _has_legacy_unlock() -> bool:
    for policy in policy_client.password_policies.values():
        if policy.status == "ACTIVE" and legacy_unlock_enabled(policy):
            return True
    return False


def _resource():
    return OktaResource(
        id="okta_account_management_policy",
        name="Okta account management policy",
    )
