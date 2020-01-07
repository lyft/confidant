import statsd

from confidant import settings

stats = statsd.StatsClient(
    settings.STATSD_HOST,
    settings.STATSD_PORT,
    prefix='confidant'
)
