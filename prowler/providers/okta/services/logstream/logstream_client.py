from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.logstream.logstream_service import LogStream

logstream_client = LogStream(Provider.get_global_provider())
