import logging

import boto3
import guard
from flask import Flask
from flask_sslify import SSLify

from confidant import settings
from confidant.routes import (
    blind_credentials,
    certificates,
    credentials,
    identity,
    saml,
    services,
    static_files,
    jwks,
)

if not settings.get('DEBUG'):
    boto3.set_stream_logger(level=logging.CRITICAL)
    logging.getLogger('botocore').setLevel(logging.CRITICAL)
    logging.getLogger('pynamodb').setLevel(logging.WARNING)

CSP_POLICY = {
    'default-src': ["'self'"],
    'style-src': [
        "'self'",
        "'unsafe-inline'"  # for spin.js
    ]
}


def create_app():
    static_folder = settings.STATIC_FOLDER

    app = Flask(__name__, static_folder=static_folder)
    app.config.from_object(settings)
    app.config.update(settings.encrypted_settings.get_all_secrets())
    app.debug = settings.DEBUG

    if settings.SSLIFY:
        SSLify(app, skips=['healthcheck'])

    app.wsgi_app = guard.ContentSecurityPolicy(app.wsgi_app, CSP_POLICY)

    if settings.REDIS_URL:
        import redis
        from flask_session import Session
        app.config['SESSION_REDIS'] = redis.Redis.from_url(
            settings.REDIS_URL
        )
        Session(app)

    app.secret_key = settings.SESSION_SECRET

    app.register_blueprint(blind_credentials.blueprint)
    app.register_blueprint(credentials.blueprint)
    app.register_blueprint(certificates.blueprint)
    app.register_blueprint(identity.blueprint)
    app.register_blueprint(saml.blueprint)
    app.register_blueprint(services.blueprint)
    app.register_blueprint(static_files.blueprint)
    app.register_blueprint(jwks.blueprint)

    return app
