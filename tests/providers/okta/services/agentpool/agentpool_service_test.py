from unittest.mock import MagicMock

import requests

from prowler.providers.okta.services.agentpool.agentpool_service import AgentPool
from tests.providers.okta.okta_fixtures import ORG_URL, set_mocked_okta_provider


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.raise_for_status = MagicMock()
    return response


class TestAgentPoolService:
    def test_lists_agent_pools_and_update_settings(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.side_effect = [
            _response(
                [
                    {
                        "id": "ad-pool",
                        "name": "AD Pool",
                        "type": "AD",
                        "agents": {"id": "agent-1", "version": "3.20.0"},
                    }
                ]
            ),
            _response({"minimalSupportedVersion": "3.19.0"}),
            _response([]),
        ]

        service = AgentPool(provider)

        assert list(service.ad_agent_pools) == ["ad-pool"]
        assert (
            service.ad_agent_pools["ad-pool"].below_minimum_supported_version is False
        )
        assert service.iwa_agent_pools == {}
        provider.session.http_session.get.assert_any_call(
            f"{ORG_URL}/api/v1/agentPools",
            params={"poolType": "AD", "limitPerPoolType": 200},
            timeout=30,
        )

    def test_skips_unavailable_iwa_agent_pools(self):
        provider = set_mocked_okta_provider(audit_config={"max_retries": 0})
        provider.session.http_session.get.side_effect = [
            _response([]),
            _bad_request_response(),
        ]

        service = AgentPool(provider)

        assert service.ad_agent_pools == {}
        assert service.iwa_agent_pools == {}


def _bad_request_response():
    response = _response({"errorSummary": "Bad request."})
    response.status_code = 400
    response.raise_for_status.side_effect = requests.exceptions.HTTPError("400")
    return response
