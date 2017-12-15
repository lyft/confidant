import boto3
from collections import defaultdict
import json

from flask.ext.script import Command, Option

from confidant.helper import (
    get_credential_context_id,
    get_services_for_credential,
    get_credential_pairs
)
from confidant.models.credential import Credential


class SearchConfidantForCredentials(Command):
    """
    This script will load a file containing a list of secrets from S3. It will
    decrypt all credentials stored in Confidant and check for the existence
    of these credentials in Confidant, whether they have been rotated or not,
    and whether they are currently in use by any service.
    """
    option_list = (
        Option(
            '--input-bucket',
            dest='input_bucket',
            required=True,
            help='Name of bucket of input file'
        ),
        Option(
            '--input-key',
            dest='input_key',
            required=True,
            help='Name of key of input file in S3'
        ),
        Option(
            '--output-bucket',
            dest='output_bucket',
            required=True,
            help='Name of bucket of output file'
        ),
        Option(
            '--output-key',
            dest='output_key',
            required=True,
            help='Name of key of output file in S3'
        ),
    )

    def __init__(self):
        self.s3_resource = boto3.resource('s3')

    def run(self, input_bucket, input_key, output_bucket, output_key):
        # Get a dict of secrets to list of Credentials they are mapped in.
        secret_to_credentials = self._get_secret_to_credential_mapping()

        # Load file from S3, read one secret per line and search for matching
        # credential
        secrets = self._load_secrets(input_bucket, input_key)

        results = []
        for secret in secrets:
            in_confidant = False
            credentials = []
            if secret in secret_to_credential:
                in_confidant = True
                for cred in secret_to_credentials[secret]:
                    if cred.data_type == 'credential':
                        services = get_services_for_credential(cred.id)
                        services = [service.id for service in services]
                        credentials.append({
                            'id': cred.id,
                            'rotated': False,
                            'services': services
                        })
                    else:
                        credentials.append({
                            'id': cred.id,
                            'rotated': True,
                            'services': []
                        })
            results.append({
                'secret_value': secret,
                'in_confidant': in_confidant,
                'credentials': credentials
            })

        # Save results to S3
        self._save_results(self, results, output_bucket, output_key)

    def _get_secret_to_credential_mapping(self):
        secret_to_credential = defaultdict(list)
        credentials = Credential.data_type_date_index.query('credential')
        for cred in credentials:
            credential_pairs = get_credential_pairs(cred)
            for val in credential_pairs.values():
                secret_to_credential[val].append(cred)

        archive_credentials = Credential.data_type_date_index.query(
            'archive-credential'
        )
        for archive_cred in archive_credentials:
            archive_cred_id = get_credential_context_id(archive_cred)
            credential_pairs = get_credential_pairs(archive_cred)
            for val in credential_pairs.values():
                # Only append an archive if the non-archived credential
                # does not contain the credential
                cred_exists = False
                for cred in secret_to_credential[val]:
                    if cred.id == archive_cred_id:
                        cred_exists = True
                        break
                if not cred_exists:
                    secret_to_credential[val].append(archive_cred)
        return secret_to_credential

    def _load_secrets(self, bucket, key):
        """
        Reads an object from S3 containing a list of secrets, each separated
        by a new line.
        """
        obj = self.s3_resource.Object(bucket, key)
        contents = obj.get()['Body'].read()
        return contents.split('\n')

    def _save_results(self, results, bucket, key):
        obj = self.s3_resource.Object(bucket, key)
        obj.put(Body=json.dumps(results), ServerSideEncryption='AES256')
