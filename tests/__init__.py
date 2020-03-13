from __future__ import absolute_import

# Load before anything to prevent infinite loop on requests.
#   See: https://github.com/gevent/gevent/issues/941
import gevent.monkey

gevent.monkey.patch_all()

import os  # noqa:E402

# pytest-env can't unset variables, and we want to avoid calling KMS when
# loading the settings.
os.environ['SECRETS_BOOTSTRAP'] = ''
