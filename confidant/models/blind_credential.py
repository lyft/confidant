from datetime import datetime

from pynamodb.models import Model
from pynamodb.attributes import (
    UnicodeAttribute,
    UnicodeSetAttribute,
    NumberAttribute,
    LegacyBooleanAttribute,
    UTCDateTimeAttribute,
    JSONAttribute
)
from pynamodb.indexes import GlobalSecondaryIndex, AllProjection

from confidant.app import app
from confidant.models.session_cls import DDBSession
from confidant.models.connection_cls import DDBConnection


class NonNullUnicodeSetAttribute(UnicodeSetAttribute):
    def __get__(self, instance, value):
        '''
        Override UnicodeSetAttribute's __get__ method to return a set, rather
        than None if the attribute isn't set.
        '''
        if instance:
            # Get the attribute. If the object doesn't have the attribute,
            # ensure we return a set.
            _value = instance.attribute_values.get(self.attr_name, set())
            # Attribute is assigned to None, return a set instead.
            if _value is None:
                _value = set()
            return _value
        else:
            return self


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
    credential_keys = NonNullUnicodeSetAttribute(default=set([]), null=True)
    enabled = LegacyBooleanAttribute(default=True)
    data_key = JSONAttribute()
    cipher_version = NumberAttribute()
    cipher_type = UnicodeAttribute()
    metadata = JSONAttribute(default={}, null=True)
    modified_date = UTCDateTimeAttribute(default=datetime.now)
    modified_by = UnicodeAttribute()
    documentation = UnicodeAttribute(null=True)
