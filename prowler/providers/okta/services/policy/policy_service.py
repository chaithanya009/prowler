from typing import Any

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.okta.exceptions.exceptions import OktaAPIError
from prowler.providers.okta.lib.service.service import OktaService

ADMIN_CONSOLE_NAME = "okta admin console"
MFA_FACTOR_MODES = frozenset(
    {
        "2FA",
        "TWO_FACTOR",
        "ANY_2_FACTORS",
        "PASSWORD_PLUS_ANY_FACTOR",
    }
)


class OktaPolicyMapping(BaseModel):
    """Okta policy resource mapping."""

    id: str
    name: str
    resource_id: str
    resource_type: str
    href: str
    raw: dict[str, Any] = Field(default_factory=dict)


class OktaPolicyRule(BaseModel):
    """Okta policy rule."""

    id: str
    name: str
    status: str
    priority: int
    conditions: dict[str, Any] = Field(default_factory=dict)
    actions: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class OktaPolicy(BaseModel):
    """Okta policy with rules and resource mappings."""

    id: str
    name: str
    type: str
    status: str
    priority: int
    system: bool
    conditions: dict[str, Any] = Field(default_factory=dict)
    settings: dict[str, Any] = Field(default_factory=dict)
    mappings: list[OktaPolicyMapping] = Field(default_factory=list)
    rules: list[OktaPolicyRule] = Field(default_factory=list)
    location: str = "global"
    raw: dict[str, Any] = Field(default_factory=dict)


class Policy(OktaService):
    """Retrieve Okta policies, policy rules, and policy mappings."""

    def __init__(self, provider):
        super().__init__("Policy", provider)
        self.access_policies = self._list_policies("ACCESS_POLICY", with_mappings=True)
        self.okta_sign_on_policies = self._list_policies("OKTA_SIGN_ON")
        self.mfa_enroll_policies = self._list_policies("MFA_ENROLL")
        self.password_policies = self._list_policies("PASSWORD", with_rules=False)

    def _list_policies(
        self,
        policy_type: str,
        with_mappings: bool = False,
        with_rules: bool = True,
    ) -> dict[str, OktaPolicy]:
        logger.info(f"Policy - Listing Okta {policy_type} policies...")
        policies = {}
        response_policies = self._get_paginated(
            "/api/v1/policies",
            params={"type": policy_type, "limit": 200},
        )

        for policy in response_policies:
            policy_id = policy["id"]
            policies[policy_id] = OktaPolicy(
                id=policy_id,
                name=policy.get("name", policy_id),
                type=policy.get("type", policy_type),
                status=str(policy.get("status", "ACTIVE")).upper(),
                priority=int(policy.get("priority", 0)),
                system=policy.get("system", False),
                conditions=_dict(policy.get("conditions")),
                settings=_dict(policy.get("settings")),
                mappings=(
                    self._list_policy_mappings(policy_id) if with_mappings else []
                ),
                rules=self._list_policy_rules(policy_id) if with_rules else [],
                raw=policy,
            )

        return policies

    def _list_policy_rules(self, policy_id: str) -> list[OktaPolicyRule]:
        rules = []
        response_rules = self._get_paginated(
            f"/api/v1/policies/{policy_id}/rules",
            params={"limit": 200},
        )

        for rule in response_rules:
            rules.append(
                OktaPolicyRule(
                    id=rule["id"],
                    name=rule.get("name", rule["id"]),
                    status=str(rule.get("status", "ACTIVE")).upper(),
                    priority=int(rule.get("priority", 0)),
                    conditions=_dict(rule.get("conditions")),
                    actions=_dict(rule.get("actions")),
                    raw=rule,
                )
            )

        return sorted(rules, key=lambda rule: rule.priority)

    def _list_policy_mappings(self, policy_id: str) -> list[OktaPolicyMapping]:
        mappings = []
        try:
            response_mappings = self._get_paginated(
                f"/api/v1/policies/{policy_id}/mappings"
            )
        except OktaAPIError:
            logger.info(f"Policy - Skipping unavailable mappings for {policy_id}.")
            return []

        for mapping in response_mappings:
            mappings.append(_parse_mapping(mapping))

        return mappings


def active_rule_requires_mfa(rule: OktaPolicyRule) -> bool:
    if rule.status != "ACTIVE":
        return False

    action = _rule_action(rule)
    if _action_denies_access(action):
        return True

    if action.get("requireFactor") is True:
        return True

    if action.get("mfaRequired") is True:
        return True

    verification = action.get("verificationMethod", {})
    factor_mode = str(verification.get("factorMode", "")).upper()
    if factor_mode in MFA_FACTOR_MODES:
        return True

    return _constraints_require_two_factors(verification.get("constraints", []))


def active_rule_allows_single_factor(rule: OktaPolicyRule) -> bool:
    if rule.status != "ACTIVE":
        return False

    action = _rule_action(rule)
    if _action_denies_access(action):
        return False

    return not active_rule_requires_mfa(rule)


def active_rule_allows_password_only_access(rule: OktaPolicyRule) -> bool:
    if rule.status != "ACTIVE":
        return False

    action = _rule_action(rule)
    if _action_denies_access(action):
        return False

    if active_rule_requires_mfa(rule):
        return False

    primary_factor = str(action.get("primaryFactor", "")).upper()
    if not primary_factor:
        return True

    return "PASSWORD" in primary_factor or "ANY_FACTOR" in primary_factor


def is_broad_rule(rule: OktaPolicyRule) -> bool:
    if rule.raw.get("system") is True:
        return True

    name = rule.name.lower()
    if "default" in name or "catch-all" in name or "everyone" in name:
        return True

    conditions = rule.conditions
    if _has_specific_people(conditions):
        return False

    if _has_specific_network(conditions):
        return False

    for condition in ("clients", "device", "platform", "risk", "userType"):
        if conditions.get(condition):
            return False

    return True


def is_broad_policy(policy: OktaPolicy) -> bool:
    if policy.system:
        return True

    name = policy.name.lower()
    if "default" in name or "everyone" in name:
        return True

    if _has_specific_people(policy.conditions):
        return False

    return not _has_specific_network(policy.conditions)


def is_admin_console_policy(policy: OktaPolicy) -> bool:
    if ADMIN_CONSOLE_NAME in policy.name.lower():
        return True

    return any(_mapping_mentions_admin_console(mapping) for mapping in policy.mappings)


def policy_has_required_enrollment(policy: OktaPolicy) -> bool:
    settings = policy.settings
    if "authenticators" in settings:
        return _authenticators_have_required_enrollment(settings["authenticators"])

    if "factors" in settings:
        return _factors_have_required_enrollment(settings["factors"])

    return False


def policy_has_known_enrollment_settings(policy: OktaPolicy) -> bool:
    settings = policy.settings
    return "authenticators" in settings or "factors" in settings


def policy_allows_authenticator(policy: OktaPolicy, key: str) -> bool:
    settings = policy.settings
    if "authenticators" in settings:
        return _authenticator_setting_allows_key(settings["authenticators"], key)

    if "factors" in settings:
        return _factor_setting_allows_key(settings["factors"], key)

    return False


def active_rule_has_finite_session_lifetime(
    rule: OktaPolicyRule, max_minutes: int
) -> bool:
    minutes = _session_value(rule, "maxSessionLifetimeMinutes")
    return minutes is not None and 0 < minutes <= max_minutes


def active_rule_has_finite_idle_timeout(rule: OktaPolicyRule, max_minutes: int) -> bool:
    minutes = _session_value(rule, "maxSessionIdleMinutes")
    return minutes is not None and 0 < minutes <= max_minutes


def active_rule_has_mfa_lifetime_setting(rule: OktaPolicyRule) -> bool:
    if rule.status != "ACTIVE":
        return False

    action = _rule_action(rule)
    if _action_denies_access(action):
        return True

    if active_rule_requires_mfa(rule):
        return True

    if "factorPromptMode" in action or "factorLifetime" in action:
        return True

    verification = _dict(action.get("verificationMethod"))
    return "reauthenticateIn" in verification


def active_rule_has_bounded_mfa_lifetime(
    rule: OktaPolicyRule, max_minutes: int
) -> bool:
    if rule.status != "ACTIVE":
        return False

    action = _rule_action(rule)
    if _action_denies_access(action):
        return True

    if str(action.get("factorPromptMode", "")).upper() == "ALWAYS":
        return True

    factor_lifetime = _positive_int(action.get("factorLifetime"))
    if factor_lifetime is not None:
        return factor_lifetime <= max_minutes

    reauthenticate_minutes = _duration_minutes(
        _dict(action.get("verificationMethod")).get("reauthenticateIn")
    )
    return reauthenticate_minutes is not None and reauthenticate_minutes <= max_minutes


def active_rule_uses_persistent_cookie(rule: OktaPolicyRule) -> bool:
    session = _dict(_rule_action(rule).get("session"))
    return session.get("usePersistentCookie") is True


def active_rule_allows_webauthn(rule: OktaPolicyRule) -> bool:
    if rule.status != "ACTIVE":
        return False

    action = _rule_action(rule)
    if _action_denies_access(action):
        return False

    return _contains_authentication_method(action, "webauthn")


def active_rule_requires_webauthn_user_verification(rule: OktaPolicyRule) -> bool:
    if not active_rule_allows_webauthn(rule):
        return True

    return _method_has_property(rule, "webauthn", "userVerification", "REQUIRED")


def active_rule_requires_managed_device(rule: OktaPolicyRule) -> bool:
    if rule.status != "ACTIVE":
        return False

    if _action_denies_access(_rule_action(rule)):
        return True

    device = _dict(rule.conditions.get("device"))
    if device.get("managed") is True and device.get("registered") is True:
        return True

    assurance = _dict(device.get("assurance"))
    if assurance.get("include"):
        return True

    return False


def is_account_management_policy(policy: OktaPolicy) -> bool:
    if "account management" in policy.name.lower():
        return True

    embedded = _dict(policy.raw.get("_embedded"))
    if str(embedded.get("resourceType", "")).upper() == "END_USER_ACCOUNT_MANAGEMENT":
        return True

    return any(
        mapping.resource_type.upper() == "END_USER_ACCOUNT_MANAGEMENT"
        for mapping in policy.mappings
    )


def password_min_length_at_least(policy: OktaPolicy, minimum: int) -> bool:
    min_length = _positive_int(_password_complexity(policy).get("minLength"))
    return min_length is not None and min_length >= minimum


def password_common_screening_enabled(policy: OktaPolicy) -> bool:
    dictionary = _dict(_password_complexity(policy).get("dictionary"))
    common = _dict(dictionary.get("common"))
    return common.get("exclude") is True


def password_lockout_enabled(policy: OktaPolicy) -> bool:
    max_attempts = _positive_int(_password_lockout(policy).get("maxAttempts"))
    return max_attempts is not None


def password_lockout_duration_finite(policy: OktaPolicy) -> bool:
    unlock_minutes = _positive_int(_password_lockout(policy).get("autoUnlockMinutes"))
    return unlock_minutes is not None


def password_rotation_disabled(policy: OktaPolicy) -> bool:
    max_age_days = _int_value(_password_age(policy).get("maxAgeDays"))
    return max_age_days == 0


def password_history_enabled(policy: OktaPolicy) -> bool:
    history_count = _positive_int(_password_age(policy).get("historyCount"))
    return history_count is not None


def legacy_sms_recovery_enabled(policy: OktaPolicy) -> bool:
    factors = _dict(_dict(policy.settings.get("recovery")).get("factors"))
    sms = _dict(factors.get("okta_sms") or factors.get("sms"))
    return str(sms.get("status", "")).upper() == "ACTIVE"


def legacy_email_recovery_enabled(policy: OktaPolicy) -> bool:
    factors = _dict(_dict(policy.settings.get("recovery")).get("factors"))
    email = _dict(factors.get("okta_email") or factors.get("email"))
    return str(email.get("status", "")).upper() == "ACTIVE"


def legacy_unlock_enabled(policy: OktaPolicy) -> bool:
    delegation = _dict(policy.settings.get("delegation"))
    options = _dict(delegation.get("options"))
    return options.get("skipUnlock") is not True


def _authenticators_have_required_enrollment(authenticators: Any) -> bool:
    if not isinstance(authenticators, list):
        return False

    for authenticator in authenticators:
        if not isinstance(authenticator, dict):
            continue
        if _enrollment_value(authenticator) == "REQUIRED":
            return True

    return False


def _factors_have_required_enrollment(factors: Any) -> bool:
    if not isinstance(factors, dict):
        return False

    for factor in factors.values():
        if not isinstance(factor, dict):
            continue
        if _enrollment_value(factor) == "REQUIRED":
            return True

    return False


def _authenticator_setting_allows_key(authenticators: Any, key: str) -> bool:
    if not isinstance(authenticators, list):
        return False

    for authenticator in authenticators:
        if not isinstance(authenticator, dict):
            continue
        if str(authenticator.get("key", "")).lower() != key:
            continue
        if _enrollment_value(authenticator) in {"DISABLED", ""}:
            continue
        return True

    return False


def _factor_setting_allows_key(factors: Any, key: str) -> bool:
    if not isinstance(factors, dict):
        return False

    for factor_key, factor in factors.items():
        if not isinstance(factor, dict):
            continue
        if key not in str(factor_key).lower():
            continue
        if _enrollment_value(factor) in {"DISABLED", ""}:
            continue
        return True

    return False


def _enrollment_value(resource: dict[str, Any]) -> str:
    enroll = resource.get("enroll", {})
    if isinstance(enroll, str):
        return enroll.upper()
    if isinstance(enroll, dict):
        return str(enroll.get("self", "")).upper()
    return ""


def _constraints_require_two_factors(constraints: Any) -> bool:
    if not isinstance(constraints, list):
        return False

    for constraint in constraints:
        if not isinstance(constraint, dict):
            continue
        factor_types = {
            factor_type
            for factor_type in ("knowledge", "possession", "inherence")
            if constraint.get(factor_type)
        }
        if len(factor_types) >= 2:
            return True

    return False


def _session_value(rule: OktaPolicyRule, field: str) -> int | None:
    if rule.status != "ACTIVE":
        return None

    action = _rule_action(rule)
    if _action_denies_access(action):
        return 1

    return _positive_int(_dict(action.get("session")).get(field))


def _password_complexity(policy: OktaPolicy) -> dict[str, Any]:
    password = _dict(policy.settings.get("password"))
    return _dict(password.get("complexity"))


def _password_age(policy: OktaPolicy) -> dict[str, Any]:
    password = _dict(policy.settings.get("password"))
    return _dict(password.get("age"))


def _password_lockout(policy: OktaPolicy) -> dict[str, Any]:
    password = _dict(policy.settings.get("password"))
    return _dict(password.get("lockout"))


def _contains_authentication_method(value: Any, method_key: str) -> bool:
    if isinstance(value, str):
        return value.lower() == method_key

    if isinstance(value, dict):
        if str(value.get("key", "")).lower() == method_key:
            return True
        if str(value.get("method", "")).lower() == method_key:
            return True
        if str(value.get("type", "")).lower() == method_key:
            return True
        return any(
            _contains_authentication_method(item, method_key) for item in value.values()
        )

    if isinstance(value, list):
        return any(_contains_authentication_method(item, method_key) for item in value)

    return False


def _method_has_property(
    rule: OktaPolicyRule, method_key: str, property_name: str, expected_value: str
) -> bool:
    return _method_property_matches(
        _rule_action(rule), method_key, property_name, expected_value
    )


def _method_property_matches(
    value: Any, method_key: str, property_name: str, expected_value: str
) -> bool:
    if isinstance(value, dict):
        nested_method = _dict(value.get(method_key))
        nested_actual = str(nested_method.get(property_name, "")).upper()
        if nested_actual == expected_value:
            return True

        matches_method = (
            str(value.get("key", "")).lower() == method_key
            or str(value.get("method", "")).lower() == method_key
            or str(value.get("type", "")).lower() == method_key
        )
        if matches_method:
            actual = str(value.get(property_name, "")).upper()
            return actual == expected_value
        return any(
            _method_property_matches(item, method_key, property_name, expected_value)
            for item in value.values()
        )

    if isinstance(value, list):
        return any(
            _method_property_matches(item, method_key, property_name, expected_value)
            for item in value
        )

    return False


def _rule_action(rule: OktaPolicyRule) -> dict[str, Any]:
    actions = rule.actions
    if "appSignOn" in actions:
        return actions["appSignOn"]
    if "signon" in actions:
        return actions["signon"]
    return {}


def _action_denies_access(action: dict[str, Any]) -> bool:
    return str(action.get("access", "")).upper() == "DENY"


def _has_specific_people(conditions: dict[str, Any]) -> bool:
    people = conditions.get("people", {})
    users = people.get("users", {})
    groups = people.get("groups", {})

    if users.get("include"):
        return True

    included_groups = groups.get("include", [])
    if not included_groups:
        return False

    return any(str(group).lower() != "everyone" for group in included_groups)


def _has_specific_network(conditions: dict[str, Any]) -> bool:
    network = conditions.get("network", {})
    connection = str(network.get("connection", "")).upper()
    if not connection or connection == "ANYWHERE":
        return False

    return True


def _mapping_mentions_admin_console(mapping: OktaPolicyMapping) -> bool:
    values = [
        mapping.name,
        mapping.resource_id,
        mapping.resource_type,
        mapping.href,
    ]
    return any(ADMIN_CONSOLE_NAME in value.lower() for value in values)


def _parse_mapping(mapping: dict[str, Any]) -> OktaPolicyMapping:
    links = _dict(mapping.get("_links"))
    resource_link = (
        links.get("application") or links.get("resource") or links.get("app") or {}
    )
    href = resource_link.get("href", "")
    resource = _dict(_dict(mapping.get("_embedded")).get("resource"))
    resource_id = mapping.get("resourceId") or resource.get("id") or _id_from_href(href)

    return OktaPolicyMapping(
        id=mapping.get("id", resource_id),
        name=(
            mapping.get("name")
            or mapping.get("resourceName")
            or resource_link.get("name")
            or resource.get("name")
            or resource.get("label")
            or ""
        ),
        resource_id=resource_id,
        resource_type=mapping.get("resourceType", resource.get("resourceType", "")),
        href=href,
        raw=mapping,
    )


def _id_from_href(href: str) -> str:
    if not href:
        return ""
    return href.rstrip("/").rsplit("/", 1)[-1]


def _dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _positive_int(value: Any) -> int | None:
    number = _int_value(value)
    if number is None or number <= 0:
        return None
    return number


def _int_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _duration_minutes(value: Any) -> int | None:
    if not isinstance(value, str) or not value.startswith("PT"):
        return None

    duration = value[2:]
    if duration.endswith("H") and duration[:-1].isdigit():
        return int(duration[:-1]) * 60
    if duration.endswith("M") and duration[:-1].isdigit():
        return int(duration[:-1])
    if duration.endswith("S") and duration[:-1].isdigit():
        return 1
    return None
