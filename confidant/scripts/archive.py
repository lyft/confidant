import sys
import logging
from datetime import datetime

from flask_script import Command, Option

from confidant import settings
from confidant.models.credential import Credential, CredentialArchive
from confidant.models.service import Service
from confidant.services import credentialmanager
from confidant.utils import stats

logger = logging.getLogger(__name__)

logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.INFO)


class ArchiveCredentials(Command):
    """
    Command to permanently archive credentials to an archive dynamodb table.
    """

    option_list = [
        Option(
            '--days',
            dest='days',
            type=int,
            help=('Permanently archive disabled credentials last modified'
                  ' greater than this many days (mutually exclusive with'
                  ' --ids)'),
        ),
        Option(
            '--force',
            action='store_true',
            dest='force',
            default=False,
            help=('By default, this script runs in dry-run mode, this option'
                  ' forces the run and makes the changes indicated by the'
                  ' dry run'),
        ),
        Option(
            '--ids',
            dest='ids',
            help=('Archive a comma separated list of credential IDs. (mutually'
                  ' exclusive with --days)'),
        ),
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
                batch.save(save)
        stats.incr('archive.save.success')

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
        with Credential.batch_write() as batch:
            for delete in deletes:
                batch.delete(delete)
        stats.incr('archive.delete.success')

    def archive(self, credentials, force):
        services = list(Service.data_type_date_index.query('service'))
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
            revisions = Credential.batch_get(
                credentialmanager.get_revision_ids_for_credential(credential)
            )
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
                stats.incr('archive.save.failure')
                continue
            try:
                self.delete(deletes, force=force)
            except Exception:
                logger.exception(
                    'Failed to batch delete {}'.format(credential.id)
                )
                stats.incr('archive.delete.failure')

    def run(self, days, force, ids):
        if not settings.DYNAMODB_TABLE_ARCHIVE:
            logger.error('DYNAMODB_TABLE_ARCHIVE is not configured, exiting.')
            return 1
        if days and ids:
            logger.error('--days and --ids options are mutually exclusive')
            return 1
        if not days and not ids:
            logger.error('Either --days or --ids options are required')
            return 1
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
        self.archive(credentials, force=force)
