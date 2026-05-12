from unittest import mock

from prowler.providers.okta.models import OktaResource
from prowler.providers.okta.services.logstream.logstream_service import OktaLogStream
from tests.providers.okta.okta_check_test_utils import load_check_with_clients

CHECK_MODULE = "prowler.providers.okta.services.logstream.logstream_active_configured.logstream_active_configured"
CLIENT_MODULE = "prowler.providers.okta.services.logstream.logstream_client"


class Test_logstream_active_configured:
    def test_active_log_stream_passes(self):
        client = _client(
            {
                "stream-1": OktaLogStream(
                    id="stream-1",
                    name="splunk",
                    status="ACTIVE",
                )
            }
        )

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"logstream_client": client}}
        ) as module:
            result = module.logstream_active_configured().execute()

        assert len(result) == 1
        assert result[0].resource_id == "okta_log_streams"
        assert result[0].status == "PASS"

    def test_no_active_log_stream_fails(self):
        client = _client({})

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"logstream_client": client}}
        ) as module:
            result = module.logstream_active_configured().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_inactive_log_stream_fails(self):
        client = _client(
            {
                "stream-1": OktaLogStream(
                    id="stream-1",
                    name="splunk",
                    status="INACTIVE",
                )
            }
        )

        with load_check_with_clients(
            CHECK_MODULE, {CLIENT_MODULE: {"logstream_client": client}}
        ) as module:
            result = module.logstream_active_configured().execute()

        assert result[0].status == "FAIL"


def _client(streams: dict[str, OktaLogStream]):
    client = mock.MagicMock()
    client.resource = OktaResource(id="okta_log_streams", name="Okta log streams")
    client.streams = streams
    return client
