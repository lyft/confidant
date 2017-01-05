import pynamodb.connection

from confidant.app import app


class DDBConnection(pynamodb.connection.Connection):
    def __init__(self, *args, **kwargs):
        super(DDBConnection, self).__init__(*args, **kwargs)
        _timeout_secs = app.config['PYNAMO_REQUEST_TIMEOUT_SECONDS']
        self._request_timeout_seconds = _timeout_secs
