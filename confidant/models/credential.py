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
    def blind(self):
        if (self.data_type.startswith('blind-') or
                self.data_type.startswith('archive-blind-')):
            return True
        else:
            return False

    @property
    def decrypted_data_key(self):
        if self.blind:
            logging.warning(
                'Calling decrypted_data_key on a blind credential.'
            )
            return None
        if self.schema_version and self.schema_version >= 2:
            _data_key = base64.b64decode(
                json.loads(self.data_key)[app.config['AWS_DEFAULT_REGION']]
            )
        else:
            _data_key = self.data_key
        return keymanager.decrypt_datakey(
            _data_key,
            encryption_context={'id': self.context}
        )

    @property
    def context(self):
        if self.data_type.startswith('archive-'):
            return self.id.split('-')[0]
        else:
            return self.id

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

    def _encrypt_and_set_pairs(self):
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
        _credential_pairs = json.dumps(self.credential_pairs)
        for region in regions:
            data_key = keymanager.create_datakey(
                encryption_context={'id': self.context},
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

    def save(self, *args, **kwargs):
        if not self.blind:
            self._encrypt_and_set_pairs()
        # Save the archive first, passing in id__null, to ensure we aren't
        # saving over an existing revision
        super(Credential, self).save(*args, id__null=True, **kwargs)
        # Reset the id and the data_type, making this a current revision to be
        # saved. We don't use id__null here because we want to overwrite the
        # entry.
        self.id = self.id.split('-')[0]
        self.data_type = self.data_type.replace('archive-', '')
        super(Credential, self).save(*args, **kwargs)
