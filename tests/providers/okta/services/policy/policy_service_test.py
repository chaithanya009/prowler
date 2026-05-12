from unittest.mock import MagicMock

import requests

from prowler.providers.okta.services.policy.policy_service import Policy
from tests.providers.okta.okta_fixtures import ORG_URL, set_mocked_okta_provider


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.status_code = 200
    response.raise_for_status = MagicMock()
    return response


def _bad_request_response():
    response = MagicMock()
    response.json.return_value = {"errorSummary": "Api validation failed: Policy"}
    response.headers = {}
    response.status_code = 400
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "400 Client Error: Bad Request"
    )
    return response


class TestPolicyService:
    def test_lists_policies_rules_and_mappings(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.side_effect = [
            _response([_policy("policy-access", "ACCESS_POLICY")]),
            _response(
                [
                    {
                        "id": "mapping-1",
                        "resourceType": "APP",
                        "_links": {
                            "application": {
                                "name": "Okta Admin Console",
                                "href": f"{ORG_URL}/api/v1/apps/app-1",
                            }
                        },
                    }
                ]
            ),
            _response([_rule("rule-access")]),
            _response([_policy("policy-signon", "OKTA_SIGN_ON")]),
            _response([_rule("rule-signon")]),
            _response([_policy("policy-mfa", "MFA_ENROLL")]),
            _response([_rule("rule-mfa")]),
            _response([_policy("policy-password", "PASSWORD")]),
        ]

        service = Policy(provider)

        assert list(service.access_policies) == ["policy-access"]
        access_policy = service.access_policies["policy-access"]
        assert access_policy.mappings[0].name == "Okta Admin Console"
        assert access_policy.mappings[0].resource_id == "app-1"
        assert access_policy.rules[0].id == "rule-access"
        assert list(service.okta_sign_on_policies) == ["policy-signon"]
        assert list(service.mfa_enroll_policies) == ["policy-mfa"]
        assert list(service.password_policies) == ["policy-password"]
        provider.session.http_session.get.assert_any_call(
            f"{ORG_URL}/api/v1/policies",
            params={"type": "ACCESS_POLICY", "limit": 200},
            timeout=30,
        )
        provider.session.http_session.get.assert_any_call(
            f"{ORG_URL}/api/v1/policies/policy-access/mappings",
            timeout=30,
        )

    def test_normalizes_nullable_policy_fields(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.side_effect = [
            _response([_policy_with_nulls("policy-access", "ACCESS_POLICY")]),
            _response([]),
            _response([_rule_with_nulls("rule-access")]),
            _response([_policy_with_nulls("policy-signon", "OKTA_SIGN_ON")]),
            _response([_rule_with_nulls("rule-signon")]),
            _response([_policy_with_nulls("policy-mfa", "MFA_ENROLL")]),
            _response([_rule_with_nulls("rule-mfa")]),
            _response([_policy_with_nulls("policy-password", "PASSWORD")]),
        ]

        service = Policy(provider)

        access_policy = service.access_policies["policy-access"]
        assert access_policy.conditions == {}
        assert access_policy.settings == {}
        assert access_policy.rules[0].conditions == {}
        assert access_policy.rules[0].actions == {}

    def test_skips_policy_mappings_when_okta_rejects_mapping_endpoint(self):
        provider = set_mocked_okta_provider(audit_config={"max_retries": 0})
        provider.session.http_session.get.side_effect = [
            _response([_policy("policy-access", "ACCESS_POLICY")]),
            _bad_request_response(),
            _response([_rule("rule-access")]),
            _response([_policy("policy-signon", "OKTA_SIGN_ON")]),
            _response([_rule("rule-signon")]),
            _response([_policy("policy-mfa", "MFA_ENROLL")]),
            _response([_rule("rule-mfa")]),
            _response([_policy("policy-password", "PASSWORD")]),
        ]

        service = Policy(provider)

        access_policy = service.access_policies["policy-access"]
        assert access_policy.mappings == []
        assert access_policy.rules[0].id == "rule-access"
        assert list(service.okta_sign_on_policies) == ["policy-signon"]
        assert list(service.mfa_enroll_policies) == ["policy-mfa"]
        assert list(service.password_policies) == ["policy-password"]


def _policy(policy_id: str, policy_type: str) -> dict:
    return {
        "id": policy_id,
        "name": "Default Policy",
        "type": policy_type,
        "status": "ACTIVE",
        "priority": 1,
        "system": True,
        "settings": {},
    }


def _rule(rule_id: str) -> dict:
    return {
        "id": rule_id,
        "name": "Default rule",
        "status": "ACTIVE",
        "priority": 1,
        "actions": {"signon": {"access": "ALLOW", "requireFactor": True}},
    }


def _policy_with_nulls(policy_id: str, policy_type: str) -> dict:
    policy = _policy(policy_id, policy_type)
    policy["conditions"] = None
    policy["settings"] = None
    return policy


def _rule_with_nulls(rule_id: str) -> dict:
    rule = _rule(rule_id)
    rule["conditions"] = None
    rule["actions"] = None
    return rule
