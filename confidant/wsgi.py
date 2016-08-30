import guard

from confidant.app import app  # noqa
from confidant import routes  # noqa

CSP_POLICY = {
    'default-src': ["'self'"],
    'style-src': [
        "'self'",
        "'unsafe-inline'"  # for spin.js
    ]
}

app.wsgi_app = guard.ContentSecurityPolicy(app.wsgi_app, CSP_POLICY)
