from datetime import datetime

from pynamodb.models import Model
from pynamodb.attributes import (
    UnicodeAttribute,
    UnicodeSetAttribute,
    NumberAttribute,
    BooleanAttribute,
    UTCDateTimeAttribute,
    JSONAttribute
)
from pynamodb.indexes import GlobalSecondaryIndex, AllProjection

from confidant.app import app
from confidant.models.session_cls import DDBSession
from confidant.models.connection_cls import DDBConnection


class DataTypeDateIndex(GlobalSecondaryIndex):
    class Meta:
        projection = AllProjection()
        read_capacity_units = 10
        write_capacity_units = 10
    data_type = UnicodeAttribute(hash_key=True)
    modified_date = UTCDateTimeAttribute(range_key=True)


class BlindCredential(Model):
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
    credential_pairs = JSONAttribute()
    credential_keys = UnicodeSetAttribute(default=set([]), null=True)
    enabled = BooleanAttribute(default=True)
    data_key = JSONAttribute()
    cipher_version = NumberAttribute()
    cipher_type = UnicodeAttribute()
    metadata = JSONAttribute(default={}, null=True)
    modified_date = UTCDateTimeAttribute(default=datetime.now)
    modified_by = UnicodeAttribute()
