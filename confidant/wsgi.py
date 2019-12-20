import gevent
import guard

from confidant.app import app  # noqa
from confidant import routes  # noqa
from confidant import settings
from confidant.services import iamrolemanager

CSP_POLICY = {
    'default-src': ["'self'"],
    'style-src': [
        "'self'",
        "'unsafe-inline'"  # for spin.js
    ]
}

app.wsgi_app = guard.ContentSecurityPolicy(app.wsgi_app, CSP_POLICY)

if settings.BACKGROUND_CACHE_IAM_ROLES:
    gevent.spawn(iamrolemanager.refresh_cache)
