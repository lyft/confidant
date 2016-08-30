import time

from pynamodb.exceptions import TableError

from confidant.app import app
from confidant.models.credential import Credential
from confidant.models.blind_credential import BlindCredential
from confidant.models.service import Service

if app.config['DYNAMODB_CREATE_TABLE']:
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
