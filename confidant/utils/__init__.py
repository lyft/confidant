import statsd

from confidant.app import app

stats = statsd.StatsClient(
    app.config['STATSD_HOST'],
    app.config['STATSD_PORT'],
    prefix='confidant'
)
