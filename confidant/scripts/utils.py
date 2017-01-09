import sys
import logging
from flask.ext.script import Command
from botocore.exceptions import ClientError

import confidant.services
from confidant import keymanager
from confidant.app import app
from confidant.models.service import Service

iam_resource = confidant.services.get_boto_resource('iam')
kms_client = confidant.services.get_boto_client('kms')

app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.INFO)


class ManageGrants(Command):

    def run(self):
        grants = keymanager.get_grants()
        try:
            roles = [x for x in iam_resource.roles.all()]
        except ClientError:
            app.logger.error('Failed to fetch IAM roles.')
            return
        services = []
        for service in Service.data_type_date_index.query('service'):
            services.append(service.id)
        for role in roles:
            if role.name in services:
                app.logger.info('Managing grants for {0}.'.format(role.name))
                keymanager._ensure_grants(role, grants)
        app.logger.info('Finished managing grants.')


class RevokeGrants(Command):

    def run(self):
        grants = keymanager.get_grants()
        for grant in grants:
            kms_client.revoke_grant(
                KeyId=keymanager.get_key_id(app.config['AUTH_KEY']),
                GrantId=grant['GrantId']
            )
        app.logger.info('Finished revoking grants.')
