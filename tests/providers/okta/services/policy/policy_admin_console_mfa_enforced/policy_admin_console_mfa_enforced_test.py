from unittest import mock

from prowler.providers.okta.services.policy.policy_service import (
    OktaPolicy,
    OktaPolicyMapping,
    OktaPolicyRule,
)
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

CHECK_MODULE = "prowler.providers.okta.services.policy.policy_admin_console_mfa_enforced.policy_admin_console_mfa_enforced"
CLIENT_MODULE = "prowler.providers.okta.services.policy.policy_client"


class Test_policy_admin_console_mfa_enforced:
    def test_admin_console_broad_rule_with_mfa_passes(self):
        client = mock.MagicMock()
        client.access_policies = {
            "policy-1": _admin_console_policy(
                OktaPolicyRule(
                    id="rule-1",
                    name="Catch-all",
                    status="ACTIVE",
                    priority=1,
                    actions={
                        "appSignOn": {
                            "access": "ALLOW",
                            "verificationMethod": {"factorMode": "2FA"},
                        }
                    },
                    raw={"system": True},
                )
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"policy_client": client}}
        ) as module:
            result = module.policy_admin_console_mfa_enforced().execute()

        assert len(result) == 1
        assert result[0].resource_id == "policy-1/rule-1"
        assert result[0].status == "PASS"

    def test_admin_console_broad_rule_with_single_factor_fails(self):
        client = mock.MagicMock()
        client.access_policies = {
            "policy-1": _admin_console_policy(
                OktaPolicyRule(
                    id="rule-1",
                    name="Catch-all",
                    status="ACTIVE",
                    priority=1,
                    actions={
                        "appSignOn": {
                            "access": "ALLOW",
                            "verificationMethod": {"factorMode": "1FA"},
                        }
                    },
                    raw={"system": True},
                )
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"policy_client": client}}
        ) as module:
            result = module.policy_admin_console_mfa_enforced().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_policy_mapping_identifies_admin_console(self):
        client = mock.MagicMock()
        client.access_policies = {
            "policy-1": _policy(
                name="Shared app policy",
                mappings=[
                    OktaPolicyMapping(
                        id="mapping-1",
                        name="Okta Admin Console",
                        resource_id="app-1",
                        resource_type="APP",
                        href="",
                    )
                ],
                rule=OktaPolicyRule(
                    id="rule-1",
                    name="Catch-all",
                    status="ACTIVE",
                    priority=1,
                    actions={
                        "appSignOn": {
                            "access": "ALLOW",
                            "verificationMethod": {"factorMode": "2FA"},
                        }
                    },
                    raw={"system": True},
                ),
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"policy_client": client}}
        ) as module:
            result = module.policy_admin_console_mfa_enforced().execute()

        assert len(result) == 1
        assert result[0].status == "PASS"


def _admin_console_policy(rule: OktaPolicyRule) -> OktaPolicy:
    return _policy(name="Okta Admin Console policy", rule=rule)


def _policy(
    name: str,
    rule: OktaPolicyRule,
    mappings: list[OktaPolicyMapping] | None = None,
) -> OktaPolicy:
    return OktaPolicy(
        id="policy-1",
        name=name,
        type="ACCESS_POLICY",
        status="ACTIVE",
        priority=1,
        system=False,
        mappings=mappings or [],
        rules=[rule],
    )
