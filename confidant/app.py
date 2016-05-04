import logging

import boto3
from flask import Flask
from flask_sslify import SSLify

from confidant import settings


if not settings.get('DEBUG'):
    boto3.set_stream_logger(level=logging.CRITICAL)
    logging.getLogger('botocore').setLevel(logging.CRITICAL)
    logging.getLogger('pynamodb').setLevel(logging.WARNING)

static_folder = settings.get('STATIC_FOLDER')

app = Flask(__name__, static_folder=static_folder)
app.config.from_object(settings)
app.debug = app.config['DEBUG']

if app.config['SSLIFY']:
    sslify = SSLify(app, skips=['healthcheck'])  # noqa

if app.config.get('REDIS_URL'):
    import redis
    from flask.ext.session import Session
    app.config['SESSION_REDIS'] = redis.Redis.from_url(
        app.config['REDIS_URL']
    )
    Session(app)

app.secret_key = app.config['SESSION_SECRET']
