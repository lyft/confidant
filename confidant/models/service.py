from confidant import app
from datetime import datetime
from pynamodb.models import Model
from pynamodb.attributes import (
    UnicodeAttribute,
    UnicodeSetAttribute,
    NumberAttribute,
    UTCDateTimeAttribute,
    BooleanAttribute
)
from pynamodb.indexes import GlobalSecondaryIndex, AllProjection


class DataTypeDateIndex(GlobalSecondaryIndex):
    class Meta:
        projection = AllProjection()
        read_capacity_units = 10
        write_capacity_units = 10
    data_type = UnicodeAttribute(hash_key=True)
    modified_date = UTCDateTimeAttribute(range_key=True)


class DataTypeRevisionIndex(GlobalSecondaryIndex):
    class Meta:
        projection = AllProjection()
        read_capacity_units = 10
        write_capacity_units = 10
    data_type = UnicodeAttribute(hash_key=True)
    revision = NumberAttribute(range_key=True)


class Service(Model):
    class Meta:
        table_name = app.config.get('DYNAMODB_TABLE')
        if app.config.get('DYNAMODB_URL'):
            host = app.config.get('DYNAMODB_URL')

    id = UnicodeAttribute(hash_key=True)
    data_type = UnicodeAttribute()
    data_type_date_index = DataTypeDateIndex()
    data_type_revision_index = DataTypeRevisionIndex()
    revision = NumberAttribute()
    enabled = BooleanAttribute(default=True)
    credentials = UnicodeSetAttribute(default=set([]))
    modified_date = UTCDateTimeAttribute(default=datetime.now)
    modified_by = UnicodeAttribute()
