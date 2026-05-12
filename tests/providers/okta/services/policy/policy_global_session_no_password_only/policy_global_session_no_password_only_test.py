from unittest import mock

from prowler.providers.okta.services.policy.policy_service import (
    OktaPolicy,
    OktaPolicyRule,
)
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

CHECK_MODULE = "prowler.providers.okta.services.policy.policy_global_session_no_password_only.policy_global_session_no_password_only"
CLIENT_MODULE = "prowler.providers.okta.services.policy.policy_client"


class Test_policy_global_session_no_password_only:
    def test_broad_rule_requiring_mfa_passes(self):
        client = mock.MagicMock()
        client.okta_sign_on_policies = {
            "policy-1": _policy(
                OktaPolicyRule(
                    id="rule-1",
                    name="Default rule",
                    status="ACTIVE",
                    priority=1,
                    actions={
                        "signon": {
                            "access": "ALLOW",
                            "primaryFactor": "PASSWORD_IDP_ANY_FACTOR",
                            "requireFactor": True,
                        }
                    },
                    raw={"system": True},
                )
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"policy_client": client}}
        ) as module:
            result = module.policy_global_session_no_password_only().execute()

        assert len(result) == 1
        assert result[0].resource_id == "policy-1/rule-1"
        assert result[0].status == "PASS"

    def test_broad_rule_allowing_password_only_fails(self):
        client = mock.MagicMock()
        client.okta_sign_on_policies = {
            "policy-1": _policy(
                OktaPolicyRule(
                    id="rule-1",
                    name="Default rule",
                    status="ACTIVE",
                    priority=1,
                    actions={
                        "signon": {
                            "access": "ALLOW",
                            "primaryFactor": "PASSWORD_IDP_ANY_FACTOR",
                            "requireFactor": False,
                        }
                    },
                    raw={"system": True},
                )
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"policy_client": client}}
        ) as module:
            result = module.policy_global_session_no_password_only().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_broad_deny_rule_passes(self):
        client = mock.MagicMock()
        client.okta_sign_on_policies = {
            "policy-1": _policy(
                OktaPolicyRule(
                    id="rule-1",
                    name="Default rule",
                    status="ACTIVE",
                    priority=1,
                    actions={"signon": {"access": "DENY"}},
                    raw={"system": True},
                )
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"policy_client": client}}
        ) as module:
            result = module.policy_global_session_no_password_only().execute()

        assert len(result) == 1
        assert result[0].status == "PASS"


def _policy(rule: OktaPolicyRule) -> OktaPolicy:
    return OktaPolicy(
        id="policy-1",
        name="Default Policy",
        type="OKTA_SIGN_ON",
        status="ACTIVE",
        priority=1,
        system=True,
        rules=[rule],
    )
