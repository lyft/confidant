import sys
import logging
from datetime import datetime

from flask_script import Command, Option

from confidant import settings
from confidant.models.credential import Credential, CredentialArchive
from confidant.services import servicemanager

logger = logging.getLogger(__name__)

logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.INFO)


class ArchiveCredentials(Command):

    option_list = [
        Option('--days', dest='days', required=True, type=int)
    ]

    def run(self, days):
        if not settings.DYNAMODB_TABLE_ARCHIVE:
            logger.error('DYNAMODB_TABLE_ARCHIVE is not configured, exiting.')
            return 1
        for credential in Credential.data_type_date_index.query('credential'):
            tz = credential.modified_date.tzinfo
            now = datetime.now(tz)
            delta = now - credential.modified_date
            if not credential.enabled and delta.days > days:
                if servicemanager.get_services_for_credential(credential.id):
                    msg = ('Skipping archival of disabled credential {}, as it'
                           ' is still mapped to a service.')
                    logger.warning(msg.format(credential.id))
                    continue
                # save the current record.
                logger.info('Archiving credential {}'.format(credential.id))
                archive_credential = CredentialArchive.from_credential(
                    credential,
                )
                archive_credential.save()
                # fetch and save every revision
                _range = range(1, credential.revision + 1)
                ids = []
                for i in _range:
                    ids.append("{0}-{1}".format(credential.id, i))
                revisions = Credential.batch_get(ids)
                for revision in revisions:
                    logger.info(
                        'Archiving credential revision {}'.format(revision.id)
                    )
                    archive_revision = CredentialArchive.from_credential(
                        revision,
                    )
                    archive_revision.save()
                    logger.info(
                        'Deleting credential revision {}'.format(revision.id)
                    )
                    revision.delete()
                logger.info('Deleting credential {}'.format(credential.id))
                credential.delete()
