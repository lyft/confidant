import sys
import time
import logging
from datetime import datetime

from flask_script import Command, Option

from confidant import settings
from confidant.models.credential import Credential, CredentialArchive
from confidant.models.service import Service

logger = logging.getLogger(__name__)

logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.INFO)


class ArchiveCredentials(Command):

    option_list = [
        Option('--days', dest='days', type=int),
        Option('--force', action='store_true', dest='force', default=False),
        Option('--ids', dest='ids'),
    ]

    def credential_in_service(self, _id, services):
        for service in services:
            if _id in service.credentials:
                return True
        return False

    def save(self, saves, force=False):
        _saves = ', '.join([save.id for save in saves])
        if not force:
            logger.info(
                'Would have archived credential and revisions: {}'.format(
                    _saves,
                )
            )
            return
        logger.info(
            'Archiving credential and revisions: {}'.format(
                _saves,
            )
        )
        with CredentialArchive.batch_write() as batch:
            for save in saves:
                while True:
                    try:
                        batch.save(save)
                        break
                    except Exception as e:
                        msg = ''
                        if hasattr(e, 'msg'):
                            msg = e.msg
                        if 'ProvisionedThroughputExceededException' in msg:
                            # Out of write capacity, sleep and try again
                            time.sleep(1)
                        else:
                            raise e

    def delete(self, deletes, force=False):
        _deletes = ', '.join([delete.id for delete in deletes])
        if not force:
            logger.info(
                'Would have deleted credential and revisions: {}'.format(
                    _deletes,
                )
            )
            return
        logger.info(
            'Deleting credential and revisions: {}'.format(
                _deletes,
            )
        )
        for delete in deletes:
            while True:
                try:
                    delete.delete()
                    break
                except Exception as e:
                    msg = ''
                    if hasattr(e, 'msg'):
                        msg = e.msg
                    if 'ProvisionedThroughputExceededException' in msg:
                        # Out of write capacity, sleep and try again
                        time.sleep(1)
                    else:
                        raise e

    def archive(self, credentials, force):
        services = [
            service for service in Service.data_type_date_index.query('service')
        ]
        for credential in credentials:
            if self.credential_in_service(credential.id, services):
                msg = ('Skipping archival of disabled credential {}, as it'
                       ' is still mapped to a service.')
                logger.warning(msg.format(credential.id))
                continue
            saves = []
            deletes = []
            # save the current record.
            archive_credential = CredentialArchive.from_credential(
                credential,
            )
            saves.append(archive_credential)
            # fetch and save every revision
            _range = range(1, credential.revision + 1)
            ids = []
            for i in _range:
                ids.append("{0}-{1}".format(credential.id, i))
            revisions = Credential.batch_get(ids)
            for revision in revisions:
                archive_revision = CredentialArchive.from_credential(
                    revision,
                )
                saves.append(archive_revision)
                deletes.append(revision)
            deletes.append(credential)
            try:
                self.save(saves, force=force)
            except Exception:
                logger.exception(
                    'Failed to batch save {}, skipping deletion.'.format(
                        credential.id
                    )
                )
                continue
            try:
                self.delete(deletes, force=force)
            except Exception:
                logger.exception(
                    'Failed to batch delete {}'.format(credential.id)
                )

    def run(self, days, force, ids):
        if not settings.DYNAMODB_TABLE_ARCHIVE:
            logger.error('DYNAMODB_TABLE_ARCHIVE is not configured, exiting.')
            return 1
        if days and ids:
            logger.error('--days and --ids options are mutually exclusive')
        if not days and not ids:
            logger.error('Either --days or --ids options are required')
        credentials = []
        if ids:
            # filter strips an empty string
            _ids = [_id.strip() for _id in list(filter(None, ids.split(',')))]
            if not _ids:
                logger.error('Passed in --ids argument is empty')
                return 1
            for credential in Credential.batch_get(_ids):
                if credential.enabled:
                    logger.warning(
                        'Skipping enabled credential {}'.format(credential.id)
                    )
                    continue
                credentials.append(credential)
        else:
            for credential in Credential.data_type_date_index.query(
                'credential'
            ):
                tz = credential.modified_date.tzinfo
                now = datetime.now(tz)
                delta = now - credential.modified_date
                if not credential.enabled and delta.days > days:
                    credentials.append(credential)
        self.archive(credentials, force)
