import sys
import logging
from flask.ext.script import Command

from confidant.app import app
from confidant.models.blind_credential import BlindCredential


app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.INFO)


def get_save_kwargs(item):
    return {}


class MigrateSetAttribute(Command):

    def run(self):
        app.logger.info('Migrating UnicodeSetAttribute in BlindCredential')
        BlindCredential.fix_unicode_set_attributes(get_save_kwargs)
        app.logger.info(BlindCredential.needs_unicode_set_fix())
