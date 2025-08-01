import asyncio
from asyncio import gather, get_event_loop
from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Entra(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)
        if self.powershell:
            self.powershell.close()

        loop = get_event_loop()
        self.tenant_domain = provider.identity.tenant_domain
        attributes = loop.run_until_complete(
            gather(
                self._get_authorization_policy(),
                self._get_conditional_access_policies(),
                self._get_admin_consent_policy(),
                self._get_groups(),
                self._get_organization(),
                self._get_users(),
            )
        )

        self.authorization_policy = attributes[0]
        self.conditional_access_policies = attributes[1]
        self.admin_consent_policy = attributes[2]
        self.groups = attributes[3]
        self.organizations = attributes[4]
        self.users = attributes[5]

    async def _get_authorization_policy(self):
        logger.info("Entra - Getting authorization policy...")
        authorization_policy = None
        try:
            auth_policy = await self.client.policies.authorization_policy.get()

            default_user_role_permissions = getattr(
                auth_policy, "default_user_role_permissions", None
            )

            authorization_policy = AuthorizationPolicy(
                id=auth_policy.id,
                name=auth_policy.display_name,
                description=auth_policy.description,
                default_user_role_permissions=DefaultUserRolePermissions(
                    allowed_to_create_apps=getattr(
                        default_user_role_permissions,
                        "allowed_to_create_apps",
                        None,
                    ),
                    allowed_to_create_security_groups=getattr(
                        default_user_role_permissions,
                        "allowed_to_create_security_groups",
                        None,
                    ),
                    allowed_to_create_tenants=getattr(
                        default_user_role_permissions,
                        "allowed_to_create_tenants",
                        None,
                    ),
                    allowed_to_read_bitlocker_keys_for_owned_device=getattr(
                        default_user_role_permissions,
                        "allowed_to_read_bitlocker_keys_for_owned_device",
                        None,
                    ),
                    allowed_to_read_other_users=getattr(
                        default_user_role_permissions,
                        "allowed_to_read_other_users",
                        None,
                    ),
                    odata_type=getattr(
                        default_user_role_permissions, "odata_type", None
                    ),
                    permission_grant_policies_assigned=[
                        policy_assigned
                        for policy_assigned in getattr(
                            default_user_role_permissions,
                            "permission_grant_policies_assigned",
                            [],
                        )
                    ],
                ),
                guest_invite_settings=auth_policy.allow_invites_from,
                guest_user_role_id=auth_policy.guest_user_role_id,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return authorization_policy

    async def _get_conditional_access_policies(self):
        logger.info("Entra - Getting conditional access policies...")
        conditional_access_policies = {}
        try:
            conditional_access_policies_list = (
                await self.client.identity.conditional_access.policies.get()
            )
            for policy in conditional_access_policies_list.value:
                conditional_access_policies[policy.id] = ConditionalAccessPolicy(
                    id=policy.id,
                    display_name=policy.display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[
                                application
                                for application in getattr(
                                    policy.conditions.applications,
                                    "include_applications",
                                    [],
                                )
                            ],
                            excluded_applications=[
                                application
                                for application in getattr(
                                    policy.conditions.applications,
                                    "exclude_applications",
                                    [],
                                )
                            ],
                            included_user_actions=[
                                UserAction(user_action)
                                for user_action in getattr(
                                    policy.conditions.applications,
                                    "include_user_actions",
                                    [],
                                )
                            ],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[
                                group
                                for group in getattr(
                                    policy.conditions.users,
                                    "include_groups",
                                    [],
                                )
                            ],
                            excluded_groups=[
                                group
                                for group in getattr(
                                    policy.conditions.users,
                                    "exclude_groups",
                                    [],
                                )
                            ],
                            included_users=[
                                user
                                for user in getattr(
                                    policy.conditions.users,
                                    "include_users",
                                    [],
                                )
                            ],
                            excluded_users=[
                                user
                                for user in getattr(
                                    policy.conditions.users,
                                    "exclude_users",
                                    [],
                                )
                            ],
                            included_roles=[
                                role
                                for role in getattr(
                                    policy.conditions.users,
                                    "include_roles",
                                    [],
                                )
                            ],
                            excluded_roles=[
                                role
                                for role in getattr(
                                    policy.conditions.users,
                                    "exclude_roles",
                                    [],
                                )
                            ],
                        ),
                        client_app_types=[
                            ClientAppType(client_app_type)
                            for client_app_type in getattr(
                                policy.conditions,
                                "client_app_types",
                                [],
                            )
                        ],
                        user_risk_levels=[
                            RiskLevel(risk_level)
                            for risk_level in getattr(
                                policy.conditions,
                                "user_risk_levels",
                                [],
                            )
                        ],
                        sign_in_risk_levels=[
                            RiskLevel(risk_level)
                            for risk_level in getattr(
                                policy.conditions,
                                "sign_in_risk_levels",
                                [],
                            )
                        ],
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=(
                            [
                                ConditionalAccessGrantControl(control.value)
                                for control in getattr(
                                    policy.grant_controls, "built_in_controls", {}
                                )
                            ]
                            if policy.grant_controls
                            else []
                        ),
                        operator=(
                            GrantControlOperator(
                                getattr(policy.grant_controls, "operator", "AND")
                            )
                        ),
                        authentication_strength=(
                            AuthenticationStrength(
                                policy.grant_controls.authentication_strength.display_name
                            )
                            if policy.grant_controls is not None
                            and policy.grant_controls.authentication_strength
                            is not None
                            else None
                        ),
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=(
                                policy.session_controls.persistent_browser.is_enabled
                                if policy.session_controls
                                and policy.session_controls.persistent_browser
                                else False
                            ),
                            mode=(
                                policy.session_controls.persistent_browser.mode
                                if policy.session_controls
                                and policy.session_controls.persistent_browser
                                else "always"
                            ),
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=(
                                policy.session_controls.sign_in_frequency.is_enabled
                                if policy.session_controls
                                and policy.session_controls.sign_in_frequency
                                else False
                            ),
                            frequency=(
                                policy.session_controls.sign_in_frequency.value
                                if policy.session_controls
                                and policy.session_controls.sign_in_frequency
                                else None
                            ),
                            type=(
                                SignInFrequencyType(
                                    policy.session_controls.sign_in_frequency.type
                                )
                                if policy.session_controls
                                and policy.session_controls.sign_in_frequency
                                and policy.session_controls.sign_in_frequency.type
                                else None
                            ),
                            interval=(
                                SignInFrequencyInterval(
                                    policy.session_controls.sign_in_frequency.frequency_interval
                                )
                                if policy.session_controls
                                and policy.session_controls.sign_in_frequency
                                else None
                            ),
                        ),
                    ),
                    state=ConditionalAccessPolicyState(
                        getattr(policy, "state", "disabled")
                    ),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return conditional_access_policies

    async def _get_admin_consent_policy(self):
        logger.info("Entra - Getting group settings...")
        admin_consent_policy = None
        try:
            policy = await self.client.policies.admin_consent_request_policy.get()
            admin_consent_policy = AdminConsentPolicy(
                admin_consent_enabled=policy.is_enabled,
                notify_reviewers=policy.notify_reviewers,
                email_reminders_to_reviewers=policy.reminders_enabled,
                duration_in_days=policy.request_duration_in_days,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return admin_consent_policy

    async def _get_groups(self):
        logger.info("Entra - Getting groups...")
        groups = []
        try:
            groups_data = await self.client.groups.get()
            for group in groups_data.value:
                groups.append(
                    Group(
                        id=group.id,
                        name=group.display_name,
                        groupTypes=group.group_types,
                        membershipRule=group.membership_rule,
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return groups

    async def _get_organization(self):
        logger.info("Entra - Getting organizations...")
        organizations = []
        try:
            org_data = await self.client.organization.get()
            for org in org_data.value:
                sync_enabled = (
                    org.on_premises_sync_enabled
                    if org.on_premises_sync_enabled is not None
                    else False
                )

                organization = Organization(
                    id=org.id,
                    name=org.display_name,
                    on_premises_sync_enabled=sync_enabled,
                )
                organizations.append(organization)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return organizations

    async def _get_users(self):
        logger.info("Entra - Getting users...")
        users = {}
        try:
            users_list = await self.client.users.get()
            directory_roles = await self.client.directory_roles.get()

            async def fetch_role_members(directory_role):
                members_response = (
                    await self.client.directory_roles.by_directory_role_id(
                        directory_role.id
                    ).members.get()
                )
                return directory_role.role_template_id, members_response.value

            tasks = [fetch_role_members(role) for role in directory_roles.value]
            roles_members_list = await asyncio.gather(*tasks)

            user_roles_map = {}
            for role_template_id, members in roles_members_list:
                for member in members:
                    user_roles_map.setdefault(member.id, []).append(role_template_id)

            try:
                registration_details_list = (
                    await self.client.reports.authentication_methods.user_registration_details.get()
                )
                registration_details = {
                    detail.id: detail for detail in registration_details_list.value
                }
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                registration_details = {}

            for user in users_list.value:
                users[user.id] = User(
                    id=user.id,
                    name=user.display_name,
                    on_premises_sync_enabled=(
                        True if (user.on_premises_sync_enabled) else False
                    ),
                    directory_roles_ids=user_roles_map.get(user.id, []),
                    is_mfa_capable=(
                        registration_details.get(user.id, {}).is_mfa_capable
                        if registration_details.get(user.id, None) is not None
                        else False
                    ),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return users


class ConditionalAccessPolicyState(Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    ENABLED_FOR_REPORTING = "enabledForReportingButNotEnforced"


class UserAction(Enum):
    REGISTER_SECURITY_INFO = "urn:user:registersecurityinfo"


class ApplicationsConditions(BaseModel):
    included_applications: List[str]
    excluded_applications: List[str]
    included_user_actions: List[UserAction]


class UsersConditions(BaseModel):
    included_groups: List[str]
    excluded_groups: List[str]
    included_users: List[str]
    excluded_users: List[str]
    included_roles: List[str]
    excluded_roles: List[str]


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    NO_RISK = "none"


class ClientAppType(Enum):
    ALL = "all"
    BROWSER = "browser"
    MOBILE_APPS_AND_DESKTOP_CLIENTS = "mobileAppsAndDesktopClients"
    EXCHANGE_ACTIVE_SYNC = "exchangeActiveSync"
    OTHER_CLIENTS = "other"


class Conditions(BaseModel):
    application_conditions: Optional[ApplicationsConditions]
    user_conditions: Optional[UsersConditions]
    client_app_types: Optional[List[ClientAppType]]
    user_risk_levels: List[RiskLevel] = []
    sign_in_risk_levels: List[RiskLevel] = []


class PersistentBrowser(BaseModel):
    is_enabled: bool
    mode: str


class SignInFrequencyInterval(Enum):
    TIME_BASED = "timeBased"
    EVERY_TIME = "everyTime"


class SignInFrequencyType(Enum):
    HOURS = "hours"
    DAYS = "days"


class SignInFrequency(BaseModel):
    is_enabled: bool
    frequency: Optional[int]
    type: Optional[SignInFrequencyType]
    interval: Optional[SignInFrequencyInterval]


class SessionControls(BaseModel):
    persistent_browser: PersistentBrowser
    sign_in_frequency: SignInFrequency


class ConditionalAccessGrantControl(Enum):
    MFA = "mfa"
    BLOCK = "block"
    DOMAIN_JOINED_DEVICE = "domainJoinedDevice"
    PASSWORD_CHANGE = "passwordChange"
    COMPLIANT_DEVICE = "compliantDevice"


class GrantControlOperator(Enum):
    AND = "AND"
    OR = "OR"


class AuthenticationStrength(Enum):
    MFA = "Multifactor authentication"
    PASSWORDLESS_MFA = "Passwordless MFA"
    PHISHING_RESISTANT_MFA = "Phishing-resistant MFA"


class GrantControls(BaseModel):
    built_in_controls: List[ConditionalAccessGrantControl]
    operator: GrantControlOperator
    authentication_strength: Optional[AuthenticationStrength]


class ConditionalAccessPolicy(BaseModel):
    id: str
    display_name: str
    conditions: Conditions
    session_controls: SessionControls
    grant_controls: GrantControls
    state: ConditionalAccessPolicyState


class DefaultUserRolePermissions(BaseModel):
    allowed_to_create_apps: Optional[bool]
    allowed_to_create_security_groups: Optional[bool]
    allowed_to_create_tenants: Optional[bool]
    allowed_to_read_bitlocker_keys_for_owned_device: Optional[bool]
    allowed_to_read_other_users: Optional[bool]
    odata_type: Optional[str]
    permission_grant_policies_assigned: Optional[List[str]] = None


class AuthorizationPolicy(BaseModel):
    id: str
    name: str
    description: str
    default_user_role_permissions: Optional[DefaultUserRolePermissions]
    guest_invite_settings: Optional[str]
    guest_user_role_id: Optional[UUID]


class Organization(BaseModel):
    id: str
    name: str
    on_premises_sync_enabled: bool


class Group(BaseModel):
    id: str
    name: str
    groupTypes: List[str]
    membershipRule: Optional[str]


class AdminConsentPolicy(BaseModel):
    admin_consent_enabled: bool
    notify_reviewers: bool
    email_reminders_to_reviewers: bool
    duration_in_days: int


class AdminRoles(Enum):
    APPLICATION_ADMINISTRATOR = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
    AUTHENTICATION_ADMINISTRATOR = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
    BILLING_ADMINISTRATOR = "b0f54661-2d74-4c50-afa3-1ec803f12efe"
    CLOUD_APPLICATION_ADMINISTRATOR = "158c047a-c907-4556-b7ef-446551a6b5f7"
    CONDITIONAL_ACCESS_ADMINISTRATOR = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
    EXCHANGE_ADMINISTRATOR = "29232cdf-9323-42fd-ade2-1d097af3e4de"
    GLOBAL_ADMINISTRATOR = "62e90394-69f5-4237-9190-012177145e10"
    GLOBAL_READER = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
    HELPDESK_ADMINISTRATOR = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
    PASSWORD_ADMINISTRATOR = "966707d0-3269-4727-9be2-8c3a10f19b9d"
    PRIVILEGED_AUTHENTICATION_ADMINISTRATOR = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
    PRIVILEGED_ROLE_ADMINISTRATOR = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    SECURITY_ADMINISTRATOR = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    SHAREPOINT_ADMINISTRATOR = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
    USER_ADMINISTRATOR = "fe930be7-5e62-47db-91af-98c3a49a38b1"


class User(BaseModel):
    id: str
    name: str
    on_premises_sync_enabled: bool
    directory_roles_ids: List[str] = []
    is_mfa_capable: bool = False


class InvitationsFrom(Enum):
    NONE = "none"
    ADMINS_AND_GUEST_INVITERS = "adminsAndGuestInviters"
    ADMINS_AND_GUEST_INVITERS_AND_MEMBERS = "adminsAndGuestInvitersAndAllMembers"
    EVERYONE = "everyone"


class AuthPolicyRoles(Enum):
    USER = UUID("a0b1b346-4d3e-4e8b-98f8-753987be4970")
    GUEST_USER = UUID("10dae51f-b6af-4016-8d66-8c2a99b929b3")
    GUEST_USER_ACCESS_RESTRICTED = UUID("2af84b1e-32c8-42b7-82bc-daa82404023b")
