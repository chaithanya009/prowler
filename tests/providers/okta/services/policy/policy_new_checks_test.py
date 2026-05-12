from unittest import mock

from prowler.providers.okta.services.policy.policy_service import (
    OktaPolicy,
    OktaPolicyMapping,
    OktaPolicyRule,
)
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

POLICY_CLIENT = "prowler.providers.okta.services.policy.policy_client"


class Test_policy_new_checks:
    def test_webauthn_user_verification_required_passes(self):
        client = _policy_client(access_rules=[_webauthn_rule("REQUIRED")])

        result = _execute("policy_webauthn_user_verification_required", client)

        assert result[0].status == "PASS"

    def test_webauthn_user_verification_preferred_fails(self):
        client = _policy_client(access_rules=[_webauthn_rule("PREFERRED")])

        result = _execute("policy_webauthn_user_verification_required", client)

        assert result[0].status == "FAIL"

    def test_global_session_lifetime_bounded_passes(self):
        client = _policy_client(signon_rules=[_signon_rule(session_lifetime=60)])

        result = _execute("policy_global_session_lifetime_bounded", client)

        assert result[0].status == "PASS"

    def test_global_session_lifetime_unbounded_fails(self):
        client = _policy_client(signon_rules=[_signon_rule(session_lifetime=0)])

        result = _execute("policy_global_session_lifetime_bounded", client)

        assert result[0].status == "FAIL"

    def test_global_session_idle_timeout_bounded_passes(self):
        client = _policy_client(signon_rules=[_signon_rule(idle_timeout=30)])

        result = _execute("policy_global_session_idle_timeout_bounded", client)

        assert result[0].status == "PASS"

    def test_global_session_idle_timeout_missing_fails(self):
        client = _policy_client(signon_rules=[_signon_rule(idle_timeout=0)])

        result = _execute("policy_global_session_idle_timeout_bounded", client)

        assert result[0].status == "FAIL"

    def test_global_session_mfa_lifetime_bounded_passes(self):
        client = _policy_client(signon_rules=[_signon_rule(factor_lifetime=60)])

        result = _execute("policy_global_session_mfa_lifetime_bounded", client)

        assert result[0].status == "PASS"

    def test_global_session_mfa_lifetime_unbounded_fails(self):
        client = _policy_client(signon_rules=[_signon_rule(factor_lifetime=0)])

        result = _execute("policy_global_session_mfa_lifetime_bounded", client)

        assert result[0].status == "FAIL"

    def test_global_session_mfa_lifetime_not_applicable_is_skipped(self):
        client = _policy_client(signon_rules=[_signon_rule_without_mfa()])

        result = _execute("policy_global_session_mfa_lifetime_bounded", client)

        assert result == []

    def test_persistent_cookie_disabled_passes(self):
        client = _policy_client(signon_rules=[_signon_rule(persistent_cookie=False)])

        result = _execute("policy_global_session_persistent_cookie_disabled", client)

        assert result[0].status == "PASS"

    def test_persistent_cookie_enabled_fails(self):
        client = _policy_client(signon_rules=[_signon_rule(persistent_cookie=True)])

        result = _execute("policy_global_session_persistent_cookie_disabled", client)

        assert result[0].status == "FAIL"

    def test_password_min_length_passes_and_fails(self):
        result = _execute(
            "policy_password_min_length_strong",
            _policy_client(password_settings=_password_settings(min_length=8)),
        )
        assert result[0].status == "PASS"

        result = _execute(
            "policy_password_min_length_strong",
            _policy_client(password_settings=_password_settings(min_length=7)),
        )
        assert result[0].status == "FAIL"

    def test_common_password_screening_passes_and_fails(self):
        result = _execute(
            "policy_password_common_screening_enabled",
            _policy_client(password_settings=_password_settings(common=True)),
        )
        assert result[0].status == "PASS"

        result = _execute(
            "policy_password_common_screening_enabled",
            _policy_client(password_settings=_password_settings(common=False)),
        )
        assert result[0].status == "FAIL"

    def test_password_lockout_passes_and_fails(self):
        result = _execute(
            "policy_password_lockout_enabled",
            _policy_client(password_settings=_password_settings(max_attempts=5)),
        )
        assert result[0].status == "PASS"

        result = _execute(
            "policy_password_lockout_enabled",
            _policy_client(password_settings=_password_settings(max_attempts=0)),
        )
        assert result[0].status == "FAIL"

    def test_password_lockout_duration_passes_and_fails(self):
        result = _execute(
            "policy_password_lockout_duration_finite",
            _policy_client(password_settings=_password_settings(unlock_minutes=15)),
        )
        assert result[0].status == "PASS"

        result = _execute(
            "policy_password_lockout_duration_finite",
            _policy_client(password_settings=_password_settings(unlock_minutes=0)),
        )
        assert result[0].status == "FAIL"

    def test_password_rotation_disabled_passes_and_fails(self):
        result = _execute(
            "policy_password_rotation_disabled",
            _policy_client(password_settings=_password_settings(max_age=0)),
        )
        assert result[0].status == "PASS"

        result = _execute(
            "policy_password_rotation_disabled",
            _policy_client(password_settings=_password_settings(max_age=90)),
        )
        assert result[0].status == "FAIL"

    def test_password_history_enabled_passes_and_fails(self):
        result = _execute(
            "policy_password_history_enabled",
            _policy_client(password_settings=_password_settings(history=4)),
        )
        assert result[0].status == "PASS"

        result = _execute(
            "policy_password_history_enabled",
            _policy_client(password_settings=_password_settings(history=0)),
        )
        assert result[0].status == "FAIL"

    def test_legacy_sms_recovery_disabled_passes_and_fails(self):
        result = _execute(
            "policy_legacy_sms_recovery_disabled",
            _policy_client(
                password_settings=_password_settings(sms_recovery="INACTIVE")
            ),
        )
        assert result[0].status == "PASS"

        result = _execute(
            "policy_legacy_sms_recovery_disabled",
            _policy_client(password_settings=_password_settings(sms_recovery="ACTIVE")),
        )
        assert result[0].status == "FAIL"

    def test_account_management_recovery_enabled_passes_and_fails(self):
        result = _execute(
            "policy_account_management_recovery_enabled",
            _policy_client(account_management=True),
        )
        assert result[0].status == "PASS"

        result = _execute(
            "policy_account_management_recovery_enabled",
            _policy_client(
                password_settings=_password_settings(email_recovery="ACTIVE")
            ),
        )
        assert result[0].status == "FAIL"

    def test_account_management_unlock_enabled_passes_and_fails(self):
        result = _execute(
            "policy_account_management_unlock_enabled",
            _policy_client(account_management=True),
        )
        assert result[0].status == "PASS"

        result = _execute(
            "policy_account_management_unlock_enabled",
            _policy_client(password_settings=_password_settings(skip_unlock=False)),
        )
        assert result[0].status == "FAIL"

    def test_admin_console_managed_device_passes_and_fails(self):
        result = _execute(
            "policy_admin_console_managed_device_required",
            _policy_client(access_rules=[_managed_device_rule(True)]),
        )
        assert result[0].status == "PASS"

        result = _execute(
            "policy_admin_console_managed_device_required",
            _policy_client(access_rules=[_managed_device_rule(False)]),
        )
        assert result[0].status == "FAIL"


def _execute(check_id, client):
    module = f"prowler.providers.okta.services.policy.{check_id}.{check_id}"
    with load_check_with_clients(
        module, {POLICY_CLIENT: {"policy_client": client}}
    ) as loaded:
        return getattr(loaded, check_id)().execute()


def _policy_client(
    access_rules=None,
    signon_rules=None,
    password_settings=None,
    account_management=False,
):
    client = mock.MagicMock()
    client.audit_config = {
        "max_global_session_lifetime_minutes": 720,
        "max_global_session_idle_minutes": 120,
        "max_mfa_lifetime_minutes": 720,
    }
    client.access_policies = {}
    if access_rules is not None:
        client.access_policies["access-policy"] = _access_policy(access_rules)
    if account_management:
        client.access_policies["account-policy"] = _access_policy(
            [_managed_device_rule(True)], name="Okta Account Management Policy"
        )
    client.okta_sign_on_policies = {}
    if signon_rules is not None:
        client.okta_sign_on_policies["signon-policy"] = _signon_policy(signon_rules)
    client.password_policies = {}
    if password_settings is not None:
        client.password_policies["password-policy"] = _password_policy(
            password_settings
        )
    return client


def _access_policy(rules, name="Okta Admin Console Policy"):
    return OktaPolicy(
        id="access-policy",
        name=name,
        type="ACCESS_POLICY",
        status="ACTIVE",
        priority=1,
        system=True,
        mappings=[
            OktaPolicyMapping(
                id="mapping-1",
                name="Okta Admin Console",
                resource_id="app-1",
                resource_type="APP",
                href="",
            )
        ],
        rules=rules,
    )


def _signon_policy(rules):
    return OktaPolicy(
        id="signon-policy",
        name="Default Global Session Policy",
        type="OKTA_SIGN_ON",
        status="ACTIVE",
        priority=1,
        system=True,
        rules=rules,
    )


def _password_policy(settings):
    return OktaPolicy(
        id="password-policy",
        name="Default Password Policy",
        type="PASSWORD",
        status="ACTIVE",
        priority=1,
        system=True,
        settings=settings,
    )


def _webauthn_rule(user_verification):
    return OktaPolicyRule(
        id="rule-1",
        name="Default rule",
        status="ACTIVE",
        priority=1,
        actions={
            "appSignOn": {
                "access": "ALLOW",
                "verificationMethod": {
                    "constraints": {
                        "possession": {
                            "authenticationMethods": [
                                {
                                    "key": "webauthn",
                                    "method": "webauthn",
                                    "userVerification": user_verification,
                                }
                            ]
                        }
                    }
                },
            }
        },
    )


def _managed_device_rule(managed):
    return OktaPolicyRule(
        id="rule-1",
        name="Default rule",
        status="ACTIVE",
        priority=1,
        conditions={"device": {"registered": managed, "managed": managed}},
        actions={"appSignOn": {"access": "ALLOW"}},
    )


def _signon_rule(
    session_lifetime=60,
    idle_timeout=30,
    factor_lifetime=60,
    persistent_cookie=False,
):
    return OktaPolicyRule(
        id="rule-1",
        name="Default rule",
        status="ACTIVE",
        priority=1,
        actions={
            "signon": {
                "access": "ALLOW",
                "factorPromptMode": "DEVICE",
                "factorLifetime": factor_lifetime,
                "session": {
                    "maxSessionLifetimeMinutes": session_lifetime,
                    "maxSessionIdleMinutes": idle_timeout,
                    "usePersistentCookie": persistent_cookie,
                },
            }
        },
    )


def _signon_rule_without_mfa():
    return OktaPolicyRule(
        id="rule-1",
        name="Default rule",
        status="ACTIVE",
        priority=1,
        actions={
            "signon": {
                "access": "ALLOW",
                "requireFactor": False,
                "session": {
                    "maxSessionLifetimeMinutes": 1440,
                    "maxSessionIdleMinutes": 120,
                },
            }
        },
    )


def _password_settings(
    min_length=8,
    common=True,
    max_attempts=5,
    unlock_minutes=15,
    max_age=0,
    history=4,
    sms_recovery="INACTIVE",
    email_recovery="INACTIVE",
    skip_unlock=True,
):
    return {
        "password": {
            "complexity": {
                "minLength": min_length,
                "dictionary": {"common": {"exclude": common}},
            },
            "lockout": {
                "maxAttempts": max_attempts,
                "autoUnlockMinutes": unlock_minutes,
            },
            "age": {"maxAgeDays": max_age, "historyCount": history},
        },
        "recovery": {
            "factors": {
                "okta_sms": {"status": sms_recovery},
                "okta_email": {"status": email_recovery},
            }
        },
        "delegation": {"options": {"skipUnlock": skip_unlock}},
    }
