from unittest import mock

from prowler.providers.okta.services.policy.policy_service import OktaPolicy
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

CHECK_MODULE = "prowler.providers.okta.services.policy.policy_authenticator_enrollment_requires_factor.policy_authenticator_enrollment_requires_factor"
CLIENT_MODULE = "prowler.providers.okta.services.policy.policy_client"


class Test_policy_authenticator_enrollment_requires_factor:
    def test_identity_engine_required_authenticator_passes(self):
        client = mock.MagicMock()
        client.mfa_enroll_policies = {
            "policy-1": _policy(
                {
                    "type": "AUTHENTICATORS",
                    "authenticators": [
                        {"key": "security_question", "enroll": {"self": "OPTIONAL"}},
                        {"key": "phone_number", "enroll": {"self": "REQUIRED"}},
                    ],
                }
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"policy_client": client}}
        ) as module:
            result = module.policy_authenticator_enrollment_requires_factor().execute()

        assert len(result) == 1
        assert result[0].resource_id == "policy-1"
        assert result[0].status == "PASS"

    def test_classic_required_factor_passes(self):
        client = mock.MagicMock()
        client.mfa_enroll_policies = {
            "policy-1": _policy(
                {
                    "factors": {
                        "okta_question": {"enroll": {"self": "OPTIONAL"}},
                        "okta_sms": {"enroll": {"self": "REQUIRED"}},
                    }
                }
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"policy_client": client}}
        ) as module:
            result = module.policy_authenticator_enrollment_requires_factor().execute()

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_classic_optional_factors_fail(self):
        client = mock.MagicMock()
        client.mfa_enroll_policies = {
            "policy-1": _policy(
                {
                    "factors": {
                        "okta_question": {"enroll": {"self": "OPTIONAL"}},
                        "okta_sms": {"enroll": {"self": "OPTIONAL"}},
                    }
                }
            )
        }

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"policy_client": client}}
        ) as module:
            result = module.policy_authenticator_enrollment_requires_factor().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_unknown_enrollment_settings_fail(self):
        client = mock.MagicMock()
        client.mfa_enroll_policies = {"policy-1": _policy({"unknown": []})}

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"policy_client": client}}
        ) as module:
            result = module.policy_authenticator_enrollment_requires_factor().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "unknown enrollment settings schema" in result[0].status_extended


def _policy(settings: dict) -> OktaPolicy:
    return OktaPolicy(
        id="policy-1",
        name="Default Policy",
        type="MFA_ENROLL",
        status="ACTIVE",
        priority=1,
        system=True,
        settings=settings,
    )
