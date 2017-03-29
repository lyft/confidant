from flask import Response

from confidant.utils import jsonutil as json


def jsonify_fast(*args, **kwargs):
    return Response(
        json.dumps(dict(*args, **kwargs)),
        mimetype='application/json'
    )
