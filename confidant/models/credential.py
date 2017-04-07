import json
import base64
import logging
from datetime import datetime

from pynamodb.models import Model
from pynamodb.attributes import (
    UnicodeSetAttribute,
    UnicodeAttribute,
    NumberAttribute,
    BooleanAttribute,
    UTCDateTimeAttribute,
    BinaryAttribute,
    JSONAttribute
)
from pynamodb.indexes import GlobalSecondaryIndex, AllProjection

from confidant.app import app
from confidant import keymanager
from confidant.ciphermanager import CipherManager
from confidant.models.session_cls import DDBSession
from confidant.models.connection_cls import DDBConnection


class EncryptError(Exception):
    pass


class DataTypeDateIndex(GlobalSecondaryIndex):
    class Meta:
        projection = AllProjection()
        read_capacity_units = 10
        write_capacity_units = 10
    data_type = UnicodeAttribute(hash_key=True)
    modified_date = UTCDateTimeAttribute(range_key=True)


class Credential(Model):
    class Meta:
        table_name = app.config.get('DYNAMODB_TABLE')
        if app.config.get('DYNAMODB_URL'):
            host = app.config.get('DYNAMODB_URL')
        region = app.config.get('AWS_DEFAULT_REGION')
        connection_cls = DDBConnection
        session_cls = DDBSession

    id = UnicodeAttribute(hash_key=True)
    revision = NumberAttribute()
    data_type = UnicodeAttribute()
    data_type_date_index = DataTypeDateIndex()
    name = UnicodeAttribute()
    blind = BooleanAttribute(null=True)
    credential_pairs = UnicodeAttribute()
    credential_keys = UnicodeSetAttribute(default=set([]), null=True)
    schema_version = NumberAttribute(null=True)
    enabled = BooleanAttribute(default=True)
    data_key = BinaryAttribute()
    cipher_type = UnicodeAttribute()
    cipher_version = NumberAttribute(null=True)
    metadata = JSONAttribute(default={}, null=True)
    modified_date = UTCDateTimeAttribute(default=datetime.now)
    modified_by = UnicodeAttribute()

    @property
    def decrypted_data_key(self):
        if self.blind:
            return None
        if self.schema_version and self.schema_version >= 2:
            _data_key = base64.b64decode(
                json.loads(self.data_key)[app.config['AWS_DEFAULT_REGION']]
            )
            logging.error('!!!DATA_KEY {0}'.format(_data_key))
        else:
            _data_key = self.data_key
        if self.data_type == 'credential':
            id_context = self.id
        else:
            id_context = self.id.split('-')[0]
        return keymanager.decrypt_datakey(
            _data_key,
            encryption_context={'id': id_context}
        )

    @property
    def decrypted_credential_pairs(self):
        if self.blind is True:
            logging.warning(
                'Calling decrypted_credential_pairs on a blind credential.'
            )
            return None
        if self.schema_version and self.schema_version >= 2:
            encrypted_credential_pairs = json.loads(
                self.credential_pairs
            )[app.config['AWS_DEFAULT_REGION']]
        else:
            encrypted_credential_pairs = self.credential_pairs
        cipher = CipherManager(self.decrypted_data_key, self.cipher_version)
        return json.loads(
            cipher.decrypt(encrypted_credential_pairs)
        )

    def encrypt_and_set_pairs(self, credential_pairs, encryption_context):
        # We only support this for blind credentials
        if self.blind:
            raise EncryptError(
                'Calling encrypt_and_set_pairs on a blind credential.'
            )
        # We explicitly use the newest cipher_version when saving new
        # credentials
        self.cipher_version = 2
        # We don't currently expose cipher_type in credentials that aren't
        # blind, so we'll set it explicitly here until we do.
        self.cipher_type = 'fernet'
        # Fetch the regions we're going to encrypt against
        regions = keymanager.get_datakey_regions()
        encrypted_credential_pairs = {}
        encrypted_data_keys = {}
        _credential_pairs = json.dumps(credential_pairs)
        for region in regions:
            data_key = keymanager.create_datakey(
                encryption_context=encryption_context,
                region=region
            )
            encrypted_data_keys[region] = base64.b64encode(
                data_key['ciphertext']
            )
            cipher = CipherManager(
                data_key['plaintext'],
                version=self.cipher_version
            )
            encrypted_credential_pairs[region] = cipher.encrypt(
                _credential_pairs
            )
        self.data_key = json.dumps(encrypted_data_keys)
        self.credential_pairs = json.dumps(encrypted_credential_pairs)
