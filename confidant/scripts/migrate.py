import sys
import logging
from flask.ext.script import Command

from confidant.app import app
from confidant.models.blind_credential import BlindCredential


app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.INFO)


class MigrateSetAttribute(Command):

    def run(self):
        app.logger.info('Migrating UnicodeSetAttribute in BlindCredential')
        for cred in BlindCredential.data_type_date_index.query(
                'blind-credential'):
            cred.save()
