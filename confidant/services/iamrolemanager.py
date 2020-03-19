import gevent
import logging
import random

import confidant.clients
from confidant import settings

logger = logging.getLogger(__name__)
ROLES = []


def refresh_cache():
    global ROLES
    refresh_rate = settings.BACKGROUND_CACHE_IAM_ROLE_REFRESH_RATE
    if settings.BACKGROUND_CACHE_IAM_ROLE_REFRESH_RATE < 60:
        refresh_rate = 60
    try:
        logger.info('Refreshing IAM roles cache.')
        ROLES = _get_iam_roles()
    except Exception:
        logger.exception(
            'Failed to update IAM roles cache.',
            exc_info=True
        )
    finally:
        # +/- 20ish seconds for respawn, to ensure all processes do not
        # refresh at the same time
        random_refresh_rate = random.randrange(
            refresh_rate - 20,
            refresh_rate + 20
        )
        return gevent.spawn_later(
            random_refresh_rate,
            refresh_cache
        )


def get_iam_roles(purge=False):
    if settings.BACKGROUND_CACHE_IAM_ROLES:
        # If the cache is empty, assume it's not populated yet, and skip cache
        if not ROLES:
            return _get_iam_roles()
        else:
            return ROLES
    else:
        return _get_iam_roles()


def _get_iam_roles():
    iam_resource = confidant.clients.get_boto_resource('iam')
    return [x.name for x in iam_resource.roles.all()]
