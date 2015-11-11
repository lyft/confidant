import sys
import logging
from flask.ext.script import Command
from botocore.exceptions import ClientError

from confidant import app
from confidant import iam
from confidant import kms
from confidant import keymanager
from confidant.models.service import Service

logging.addHandler(logging.StreamHandler(sys.stdout))
logging.setLevel(logging.INFO)


class ManageGrants(Command):

    def run(self):
        grants = keymanager.get_grants()
        try:
            roles = [x for x in iam.roles.all()]
        except ClientError:
            logging.error('Failed to fetch IAM roles.')
            return
        services = []
        for service in Service.data_type_date_index.query('service'):
            services.append(service.id)
        for role in roles:
            if role.name in services:
                logging.info('Managing grants for {0}.'.format(role.name))
                keymanager._ensure_grants(role, grants)
        logging.info('Finished managing grants.')


class RevokeGrants(Command):

    def run(self):
        grants = keymanager.get_grants()
        for grant in grants:
            kms.revoke_grant(
                KeyId=keymanager.get_key_id(app.config['AUTH_KEY']),
                GrantId=grant['GrantId']
            )
        logging.info('Finished revoking grants.')
