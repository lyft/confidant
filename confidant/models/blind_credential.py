from datetime import datetime

from pynamodb.models import Model
from pynamodb.attributes import (
    UnicodeAttribute,
    NumberAttribute,
    BooleanAttribute,
    UTCDateTimeAttribute,
    JSONAttribute
)
from pynamodb.indexes import GlobalSecondaryIndex, AllProjection

from confidant import settings
from confidant.models.session_cls import DDBSession
from confidant.models.connection_cls import DDBConnection
from confidant.models.non_null_unicode_set_attribute import (
    NonNullUnicodeSetAttribute
)


class DataTypeDateIndex(GlobalSecondaryIndex):
    class Meta:
        projection = AllProjection()
        read_capacity_units = 10
        write_capacity_units = 10
    data_type = UnicodeAttribute(hash_key=True)
    modified_date = UTCDateTimeAttribute(range_key=True)


class BlindCredential(Model):
    class Meta:
        table_name = settings.DYNAMODB_TABLE
        if settings.DYNAMODB_URL:
            host = settings.DYNAMODB_URL
        region = settings.AWS_DEFAULT_REGION
        connection_cls = DDBConnection
        session_cls = DDBSession

    id = UnicodeAttribute(hash_key=True)
    revision = NumberAttribute()
    data_type = UnicodeAttribute()
    data_type_date_index = DataTypeDateIndex()
    name = UnicodeAttribute()
    credential_pairs = JSONAttribute()
    credential_keys = NonNullUnicodeSetAttribute(default=set, null=True)
    enabled = BooleanAttribute(default=True)
    data_key = JSONAttribute()
    cipher_version = NumberAttribute()
    cipher_type = UnicodeAttribute()
    metadata = JSONAttribute(default=dict, null=True)
    modified_date = UTCDateTimeAttribute(default=datetime.now)
    modified_by = UnicodeAttribute()
    documentation = UnicodeAttribute(null=True)

    def equals(self, other_cred):
        if self.name != other_cred.name:
            return False
        if self.credential_pairs != other_cred.credential_pairs:
            return False
        if self.credential_keys != other_cred.credential_keys:
            return False
        if self.enabled != other_cred.enabled:
            return False
        if self.data_key != other_cred.data_key:
            return False
        if self.cipher_version != other_cred.cipher_version:
            return False
        if self.cipher_type != other_cred.cipher_type:
            return False
        if self.metadata != other_cred.metadata:
            return False
        if self.documentation != other_cred.documentation:
            return False
        return True
