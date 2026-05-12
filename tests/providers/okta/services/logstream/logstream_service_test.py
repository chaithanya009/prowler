from unittest.mock import MagicMock

from prowler.providers.okta.services.logstream.logstream_service import LogStream
from tests.providers.okta.okta_fixtures import ORG_URL, set_mocked_okta_provider


def _response(payload, headers=None):
    response = MagicMock()
    response.json.return_value = payload
    response.headers = headers or {}
    response.raise_for_status = MagicMock()
    return response


class TestLogStreamService:
    def test_lists_log_streams(self):
        provider = set_mocked_okta_provider()
        provider.session.http_session.get.return_value = _response(
            [{"id": "stream-1", "name": "splunk", "status": "ACTIVE"}]
        )

        service = LogStream(provider)

        assert list(service.streams) == ["stream-1"]
        assert service.streams["stream-1"].name == "splunk"
        assert service.streams["stream-1"].status == "ACTIVE"
        provider.session.http_session.get.assert_called_once_with(
            f"{ORG_URL}/api/v1/logStreams",
            timeout=30,
        )
