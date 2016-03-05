import statsd

from confidant.app import app
from confidant.utils import lru

stats = statsd.StatsClient(
    app.config['STATSD_HOST'],
    app.config['STATSD_PORT'],
    prefix='confidant'
)

cache = lru.LRUCache(2048)
