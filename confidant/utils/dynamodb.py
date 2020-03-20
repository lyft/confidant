import base64
import json
import time

from pynamodb.exceptions import TableError

from confidant import settings
from confidant.models.credential import Credential, CredentialArchive
from confidant.models.blind_credential import BlindCredential
from confidant.models.service import Service


def create_dynamodb_tables():
    i = 0
    # This loop is absurd, but there's race conditions with dynamodb local
    while i < 5:
        try:
            if not Credential.exists():
                Credential.create_table(
                    read_capacity_units=10,
                    write_capacity_units=10,
                    wait=True
                )
            if (settings.DYNAMODB_TABLE_ARCHIVE
                    and not CredentialArchive.exists()):
                CredentialArchive.create_table(
                    read_capacity_units=10,
                    write_capacity_units=10,
                    wait=True
                )
            if not BlindCredential.exists():
                BlindCredential.create_table(
                    read_capacity_units=10,
                    write_capacity_units=10,
                    wait=True
                )
            if not Service.exists():
                Service.create_table(
                    read_capacity_units=10,
                    write_capacity_units=10,
                    wait=True
                )
            break
        except TableError:
            i = i + 1
            time.sleep(2)


def encode_last_evaluated_key(last_evaluated_key):
    if not last_evaluated_key:
        return None
    str_key = json.dumps(last_evaluated_key)
    return base64.b64encode(str_key.encode('UTF-8')).decode('UTF-8')


def decode_last_evaluated_key(last_evaluated_key):
    if not last_evaluated_key:
        return None
    return json.loads(base64.b64decode(last_evaluated_key))
