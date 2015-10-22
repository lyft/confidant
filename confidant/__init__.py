import boto3
import logging
import redis

from flask import Flask
from flask.ext.session import Session
from flask_sslify import SSLify
from confidant import lru
from confidant import settings

if not settings.get('DEBUG'):
    boto3.set_stream_logger(level=logging.CRITICAL)
    logging.getLogger('botocore').setLevel(logging.CRITICAL)
    logging.getLogger('pynamodb').setLevel(logging.WARNING)
log = logging.getLogger(__name__)

static_folder = settings.get('STATIC_FOLDER')

app = Flask(__name__, static_folder=static_folder)
app.config.from_object(settings)
app.debug = app.config['DEBUG']

if app.config['SSLIFY']:
    sslify = SSLify(app, skips=['healthcheck'])

cache = lru.LRUCache(2048)

if app.config.get('REDIS_URL'):
    app.config['SESSION_REDIS'] = redis.Redis.from_url(
        app.config['REDIS_URL']
    )
    Session(app)

app.secret_key = app.config['SESSION_SECRET']

import statsd
stats = statsd.StatsClient(
    app.config['STATSD_HOST'],
    app.config['STATSD_PORT'],
    prefix='confidant'
)

kms = boto3.client('kms')
iam = boto3.resource('iam')

from confidant import routes  # noqa
