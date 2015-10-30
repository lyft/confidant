import sys
import logging

from flask.ext.script import Command
from confidant import app
from confidant import iam
from confidant import kms
from confidant import log
from confidant import keymanager
from confidant.models.service import Service
from botocore.exceptions import ClientError

log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.INFO)


class ManageGrants(Command):

    def run(self):
        grants = keymanager.get_grants()
        try:
            roles = [x for x in iam.roles.all()]
        except ClientError:
            log.error('Failed to fetch IAM roles.')
            return
        services = []
        for service in Service.data_type_date_index.query('service'):
            services.append(service.id)
        for role in roles:
            if role.name in services:
                log.info('Managing grants for {0}.'.format(role.name))
                keymanager._ensure_grants(role, grants)
        log.info('Finished managing grants.')


class RevokeGrants(Command):

    def run(self):
        grants = keymanager.get_grants()
        for grant in grants:
            kms.revoke_grant(
                KeyId=keymanager.get_key_id(app.config['AUTH_KEY']),
                GrantId=grant['GrantId']
            )
        log.info('Finished revoking grants.')
