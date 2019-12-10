import json
from datetime import datetime

from pynamodb.models import Model
from pynamodb.attributes import (
    UnicodeAttribute,
    NumberAttribute,
    BooleanAttribute,
    UTCDateTimeAttribute,
    BinaryAttribute,
    JSONAttribute
)
from pynamodb.indexes import GlobalSecondaryIndex, AllProjection

from confidant.app import app
from confidant.models.session_cls import DDBSession
from confidant.models.connection_cls import DDBConnection
from confidant.services import keymanager
from confidant.services.ciphermanager import CipherManager


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
    enabled = BooleanAttribute(default=True)
    data_key = BinaryAttribute()
    # TODO: add cipher_type
    cipher_version = NumberAttribute(null=True)
    metadata = JSONAttribute(default=dict, null=True)
    modified_date = UTCDateTimeAttribute(default=datetime.now)
    modified_by = UnicodeAttribute()
    documentation = UnicodeAttribute(null=True)

    def equals(self, other_cred):
        if self.name != other_cred.name:
            return False
        if self.decrypted_credential_pairs != other_cred.decrypted_credential_pairs:  # noqa:E501
            return False
        if self.metadata != other_cred.metadata:
            return False
        if self.enabled != other_cred.enabled:
            return False
        if self.documentation != other_cred.documentation:
            return False
        return True

    @property
    def decrypted_credential_pairs(self):
        if self.data_type == 'credential':
            context = self.id
        else:
            context = self.id.split('-')[0]
        data_key = keymanager.decrypt_datakey(
            self.data_key,
            encryption_context={'id': context}
        )
        cipher_version = self.cipher_version
        cipher = CipherManager(data_key, cipher_version)
        _credential_pairs = cipher.decrypt(self.credential_pairs)
        _credential_pairs = json.loads(_credential_pairs)
        return _credential_pairs
