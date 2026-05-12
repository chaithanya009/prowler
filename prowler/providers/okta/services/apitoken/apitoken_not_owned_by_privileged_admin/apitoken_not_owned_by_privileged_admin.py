from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.apitoken.apitoken_client import api_token_client
from prowler.providers.okta.services.user.user_client import user_client

PRIVILEGED_TOKEN_OWNER_ROLES = frozenset({"ORG_ADMIN", "SUPER_ADMIN"})


class apitoken_not_owned_by_privileged_admin(Check):
    """Ensure SSWS API tokens are not owned by Super Admin or Org Admin users."""

    def execute(self) -> list[CheckReportOkta]:
        findings = []
        active_tokens = [
            token
            for token in api_token_client.tokens.values()
            if token.status == "ACTIVE"
        ]

        if not active_tokens:
            report = CheckReportOkta(
                metadata=self.metadata(),
                resource=api_token_client.resource,
            )
            report.status = "PASS"
            report.status_extended = "Okta has no active SSWS API tokens."
            return [report]

        for token in active_tokens:
            report = CheckReportOkta(metadata=self.metadata(), resource=token)
            owner = user_client.users.get(token.user_id)
            owner_roles = set(owner.roles if owner else [])
            privileged_roles = owner_roles & PRIVILEGED_TOKEN_OWNER_ROLES

            if privileged_roles:
                report.status = "FAIL"
                report.status_extended = (
                    f"Okta SSWS API token {token.name} is owned by a user with "
                    f"{', '.join(sorted(privileged_roles))}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Okta SSWS API token {token.name} is not owned by a Super "
                    f"Admin or Org Admin user."
                )

            findings.append(report)

        return findings
