import guard

from confidant import app, settings

CSP_POLICY = {
    'default-src': ["'self'"],
    'style-src': [
        "'self'",
        "'unsafe-inline'"  # for spin.js
        ]
    }

app.wsgi_app = guard.ContentSecurityPolicy(app.wsgi_app, CSP_POLICY)

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=settings.get('PORT', 5000),
        debug=settings.get('DEBUG', True))
