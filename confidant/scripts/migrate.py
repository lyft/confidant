import sys
import logging
from flask.ext.script import Command

from confidant.app import app
from confidant.models.blind_credential import BlindCredential


app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.INFO)


class MigrateSetAttribute(Command):

    def get_save_kwargs():
        return {}

    def run(self):
        app.logger.info('Migrating UnicodeSetAttribute in BlindCredential')
        BlindCredential.fix_unicode_set_attributes(self.get_save_kwargs)
        app.logger.info(BlindCredential.needs_unicode_set_fix())
