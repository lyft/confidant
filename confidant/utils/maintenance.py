import logging
import json
import os.path
from functools import wraps

from flask import make_response

from confidant import settings

logger = logging.getLogger(__name__)


def in_maintenance_mode():
    # We're in maintenance mode if the config option is explicitly set, or if
    # the touch file exists.
    maintenance_mode = settings.MAINTENANCE_MODE
    _maintenance_touch_file = settings.MAINTENANCE_MODE_TOUCH_FILE
    if _maintenance_touch_file and os.path.exists(_maintenance_touch_file):
        maintenance_mode = True
    return maintenance_mode


def check_maintenance_mode(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Return an error if this function is called when the app is in
        # maintenance mode.
        if in_maintenance_mode():
            logger.warning('Rejecting request due to maintenance mode.')
            resp = make_response(
                json.dumps({'error': 'Server in maintenance mode.'}),
                403
            )
            resp.mimetype = 'application/json'
            return resp
        else:
            return f(*args, **kwargs)
    return decorated
