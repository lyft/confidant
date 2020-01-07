import gevent

from confidant import settings
from confidant.app import create_app  # noqa
from confidant.services import iamrolemanager

app = create_app()

if settings.BACKGROUND_CACHE_IAM_ROLES:
    gevent.spawn(iamrolemanager.refresh_cache)
