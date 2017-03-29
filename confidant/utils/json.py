import logging
import json

import ujson


def dumps(*args, **kwargs):
    try:
        ret = ujson.dumps(*args, escape_forward_slashes=False, **kwargs)
    except Exception:
        logging.warning('ujson dumps error. Falling back to json.')
        ret = json.dumps(*args, **kwargs)
    return ret


def loads(*args, **kwargs):
    try:
        ret = ujson.loads(*args, **kwargs)
    except Exception:
        logging.warning('ujson loads error. Falling back to json.')
        ret = json.loads(*args, **kwargs)
    return ret
