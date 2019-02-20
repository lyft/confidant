from datetime import datetime

from pynamodb.models import Model
from pynamodb.attributes import (
    UnicodeAttribute,
    NumberAttribute,
    UTCDateTimeAttribute,
    BooleanAttribute
)
from pynamodb.indexes import GlobalSecondaryIndex, AllProjection

from confidant.app import app
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


class Service(Model):
    class Meta:
        table_name = app.config.get('DYNAMODB_TABLE')
        if app.config.get('DYNAMODB_URL'):
            host = app.config.get('DYNAMODB_URL')
        region = app.config.get('AWS_DEFAULT_REGION')
        connection_cls = DDBConnection
        session_cls = DDBSession

    id = UnicodeAttribute(hash_key=True)
    data_type = UnicodeAttribute()
    data_type_date_index = DataTypeDateIndex()
    revision = NumberAttribute()
    enabled = BooleanAttribute(default=True)
    credentials = NonNullUnicodeSetAttribute(default=set)
    blind_credentials = NonNullUnicodeSetAttribute(default=set)
    account = UnicodeAttribute(null=True)
    modified_date = UTCDateTimeAttribute(default=datetime.now)
    modified_by = UnicodeAttribute()
