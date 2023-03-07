import sys
import logging
from datetime import datetime

from flask_script import Command, Option

from confidant import settings
from confidant.models.credential import Credential
from confidant.services import credentialmanager

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

        credentialmanager.archive_credentials(credentials, force=force)
