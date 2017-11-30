from functools import wraps

from flask import make_response

from confidant.app import app


def check_maintenance_mode(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Return an error if this function is called when the app is in
        # maintenance mode.
        if app.config.get('MAINTENANCE_MODE'):
            return make_response(
                "{'error': 'Server in maintenance mode.'}",
                403,
                mimetype='application/json'
            )
        else:
            return f(*args, **kwargs)
    return decorated
