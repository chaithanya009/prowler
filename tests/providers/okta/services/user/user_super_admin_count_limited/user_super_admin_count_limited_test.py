from unittest import mock

from prowler.providers.okta.models import OktaResource
from prowler.providers.okta.services.user.user_service import OktaUser
from tests.providers.okta.okta_check_test_utils import load_check_with_clients
from tests.providers.okta.okta_fixtures import USER_EMAIL, USER_ID, USER_LOGIN

CHECK_MODULE = "prowler.providers.okta.services.user.user_super_admin_count_limited.user_super_admin_count_limited"
CLIENT_MODULE = "prowler.providers.okta.services.user.user_client"


class Test_user_super_admin_count_limited:
    def test_three_super_admins_pass_by_default(self):
        client = _client(
            users={
                "00u1": _user("00u1", "admin1@example.com", ["SUPER_ADMIN"]),
                "00u2": _user("00u2", "admin2@example.com", ["SUPER_ADMIN"]),
                "00u3": _user("00u3", "admin3@example.com", ["SUPER_ADMIN"]),
            }
        )

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"user_client": client}}
        ) as module:
            result = module.user_super_admin_count_limited().execute()

        assert len(result) == 1
        assert result[0].resource_id == "okta_admin_roles"
        assert result[0].status == "PASS"

    def test_four_super_admins_fail_by_default(self):
        client = _client(
            users={
                "00u1": _user("00u1", "admin1@example.com", ["SUPER_ADMIN"]),
                "00u2": _user("00u2", "admin2@example.com", ["SUPER_ADMIN"]),
                "00u3": _user("00u3", "admin3@example.com", ["SUPER_ADMIN"]),
                "00u4": _user("00u4", "admin4@example.com", ["SUPER_ADMIN"]),
            }
        )

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"user_client": client}}
        ) as module:
            result = module.user_super_admin_count_limited().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_custom_threshold_is_used(self):
        client = _client(
            audit_config={"max_super_admins": 4},
            users={
                "00u1": _user("00u1", "admin1@example.com", ["SUPER_ADMIN"]),
                "00u2": _user("00u2", "admin2@example.com", ["SUPER_ADMIN"]),
                "00u3": _user("00u3", "admin3@example.com", ["SUPER_ADMIN"]),
                "00u4": _user("00u4", "admin4@example.com", ["SUPER_ADMIN"]),
            },
        )

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"user_client": client}}
        ) as module:
            result = module.user_super_admin_count_limited().execute()

        assert result[0].status == "PASS"


def _client(users: dict[str, OktaUser], audit_config: dict | None = None):
    client = mock.MagicMock()
    client.audit_config = audit_config or {}
    client.resource = OktaResource(id="okta_admin_roles", name="Okta admin roles")
    client.users = users
    return client


def _user(user_id: str, login: str, roles: list[str]) -> OktaUser:
    return OktaUser(
        id=user_id or USER_ID,
        login=login or USER_LOGIN,
        email=USER_EMAIL,
        status="ACTIVE",
        roles=roles,
    )
