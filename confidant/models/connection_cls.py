import pynamodb.connection

from confidant import settings


class DDBConnection(pynamodb.connection.Connection):
    def __init__(self, *args, **kwargs):
        super(DDBConnection, self).__init__(*args, **kwargs)
        _timeout_secs = settings.PYNAMO_REQUEST_TIMEOUT_SECONDS
        self._request_timeout_seconds = _timeout_secs
