from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService
from prowler.providers.okta.models import OktaResource


class OktaLogStream(BaseModel):
    """Okta log stream integration."""

    id: str
    name: str
    status: str
    location: str = "global"


class LogStream(OktaService):
    """Retrieve Okta log streams."""

    def __init__(self, provider):
        super().__init__("LogStream", provider)
        self.resource = OktaResource(id="okta_log_streams", name="Okta log streams")
        self.streams = self._list_streams()

    def _list_streams(self) -> dict[str, OktaLogStream]:
        logger.info("LogStream - Listing Okta log streams...")
        streams = {}
        response_streams = self._get_paginated("/api/v1/logStreams")

        for stream in response_streams:
            stream_id = stream["id"]
            streams[stream_id] = OktaLogStream(
                id=stream_id,
                name=stream.get("name", stream_id),
                status=str(stream.get("status", stream.get("state", ""))).upper(),
            )

        return streams
