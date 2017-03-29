from flask import Response

from confidant.utils import json as json


def jsonify_fast(*args, **kwargs):
    return Response(
        json.dumps(dict(*args, **kwargs)),
        mimetype='application/json'
    )
