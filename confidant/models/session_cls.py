from botocore.vendored.requests import Session as BotoRequestsSession
from botocore.vendored.requests.adapters import HTTPAdapter as BotoHTTPAdapter

from confidant import settings


class DDBSession(BotoRequestsSession):
    def __init__(self):
        super(DDBSession, self).__init__()
        self.mount('https://', BotoHTTPAdapter(
            pool_maxsize=settings.PYNAMO_CONNECTION_POOL_SIZE
        ))
        self.mount('http://', BotoHTTPAdapter(
            pool_maxsize=settings.PYNAMO_CONNECTION_POOL_SIZE
        ))
