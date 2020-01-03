# Load before anything to prevent infinite loop on requests
#   See: https://github.com/gevent/gevent/issues/941
import gevent.monkey

gevent.monkey.patch_all()
