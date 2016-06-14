import guard

import confidant.workarounds  # noqa
from confidant.app import app

CSP_POLICY = {
    'default-src': ["'self'"],
    'style-src': [
        "'self'",
        "'unsafe-inline'"  # for spin.js
    ]
}

app.wsgi_app = guard.ContentSecurityPolicy(app.wsgi_app, CSP_POLICY)

from confidant import routes  # noqa

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=app.config.get('PORT', 5000),
        debug=app.config.get('DEBUG', True)
    )
