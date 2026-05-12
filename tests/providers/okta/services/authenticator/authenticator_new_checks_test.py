from unittest import mock

from prowler.providers.okta.models import OktaResource
from prowler.providers.okta.services.policy.policy_service import OktaPolicy
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

AUTH_CLIENT = "prowler.providers.okta.services.authenticator.authenticator_client"
POLICY_CLIENT = "prowler.providers.okta.services.policy.policy_client"


class Test_authenticator_new_checks:
    def test_passkey_enabled_passes(self):
        authenticator_client = _auth_client(authenticators={"webauthn"})
        policy_client = mock.MagicMock()
        policy_client.mfa_enroll_policies = {
            "policy-1": _mfa_policy(
                [{"key": "webauthn", "enroll": {"self": "OPTIONAL"}}]
            )
        }

        result = _execute(
            "authenticator_passkey_enabled",
            authenticator_client,
            policy_client,
        )

        assert result[0].status == "PASS"

    def test_passkey_missing_fails(self):
        result = _execute(
            "authenticator_passkey_enabled", _auth_client(), _policy_client()
        )

        assert result[0].status == "FAIL"

    def test_fastpass_enabled_passes(self):
        result = _execute(
            "authenticator_fastpass_enabled",
            _auth_client(methods={"signed_nonce"}),
        )

        assert result[0].status == "PASS"

    def test_fastpass_missing_fails(self):
        result = _execute("authenticator_fastpass_enabled", _auth_client())

        assert result[0].status == "FAIL"

    def test_sms_disabled_passes(self):
        result = _execute("authenticator_sms_disabled", _auth_client())

        assert result[0].status == "PASS"

    def test_sms_active_fails(self):
        result = _execute("authenticator_sms_disabled", _auth_client(methods={"sms"}))

        assert result[0].status == "FAIL"

    def test_voice_disabled_passes(self):
        result = _execute("authenticator_voice_disabled", _auth_client())

        assert result[0].status == "PASS"

    def test_voice_active_fails(self):
        result = _execute(
            "authenticator_voice_disabled", _auth_client(methods={"voice"})
        )

        assert result[0].status == "FAIL"

    def test_security_question_disabled_passes(self):
        result = _execute("authenticator_security_question_disabled", _auth_client())

        assert result[0].status == "PASS"

    def test_security_question_active_fails(self):
        result = _execute(
            "authenticator_security_question_disabled",
            _auth_client(authenticators={"security_question"}),
        )

        assert result[0].status == "FAIL"

    def test_okta_verify_enabled_passes(self):
        result = _execute(
            "authenticator_okta_verify_enabled",
            _auth_client(authenticators={"okta_verify"}),
        )

        assert result[0].status == "PASS"

    def test_okta_verify_missing_fails(self):
        result = _execute("authenticator_okta_verify_enabled", _auth_client())

        assert result[0].status == "FAIL"


def _execute(check_id, authenticator_client, policy_client=None):
    module = f"prowler.providers.okta.services.authenticator.{check_id}.{check_id}"
    check_client_modules = {AUTH_CLIENT: {"authenticator_client": authenticator_client}}
    if policy_client is not None:
        check_client_modules[POLICY_CLIENT] = {"policy_client": policy_client}

    with load_check_with_clients(module, check_client_modules) as loaded:
        return getattr(loaded, check_id)().execute()


def _auth_client(methods=None, authenticators=None):
    methods = methods or set()
    authenticators = authenticators or set()
    client = mock.MagicMock()
    client.resource = OktaResource(id="okta_authenticators", name="Okta authenticators")
    client.has_active_method.side_effect = lambda method: method in methods
    client.has_active_authenticator.side_effect = lambda keys: bool(
        set(keys) & authenticators
    )
    return client


def _policy_client():
    client = mock.MagicMock()
    client.mfa_enroll_policies = {}
    return client


def _mfa_policy(authenticators):
    return OktaPolicy(
        id="policy-1",
        name="Default Enrollment",
        type="MFA_ENROLL",
        status="ACTIVE",
        priority=1,
        system=True,
        settings={"authenticators": authenticators},
    )
