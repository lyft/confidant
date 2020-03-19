from datetime import datetime

from pynamodb.models import Model
from pynamodb.attributes import (
    UnicodeAttribute,
    NumberAttribute,
    UTCDateTimeAttribute,
    BooleanAttribute
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


class Service(Model):
    class Meta:
        table_name = settings.DYNAMODB_TABLE
        if settings.DYNAMODB_URL:
            host = settings.DYNAMODB_URL
        region = settings.AWS_DEFAULT_REGION
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

    def equals(self, other_service):
        if set(self.credentials) != set(other_service.credentials):
            return False
        if set(self.blind_credentials) != set(other_service.blind_credentials):
            return False
        if self.account != other_service.account:
            return False
        return True

    def diff(self, other_service):
        if self.revision == other_service.revision:
            return {}
        elif self.revision > other_service.revision:
            old = other_service
            new = self
        else:
            old = self
            new = other_service
        diff = {}
        if old.enabled != new.enabled:
            diff['enabled'] = {'added': new.enabled, 'removed': old.enabled}
        if set(old.credentials) != set(new.credentials):
            diff['credentials'] = self._diff_list(
                old.credentials,
                new.credentials,
            )
        if set(old.blind_credentials) != set(new.blind_credentials):
            diff['blind_credentials'] = self._diff_list(
                old.blind_credentials,
                new.blind_credentials,
            )
        if old.account != new.account:
            diff['account'] = {'added': new.account, 'removed': old.account}
        diff['modified_by'] = {
            'added': new.modified_by,
            'removed': old.modified_by,
        }
        diff['modified_date'] = {
            'added': new.modified_date,
            'removed': old.modified_date,
        }
        return diff

    def _diff_list(self, old, new):
        diff = {}
        removed = []
        added = []
        for key in old:
            if key not in new:
                removed.append(key)
        for key in new:
            if key not in old:
                added.append(key)
        if removed:
            diff['removed'] = sorted(removed)
        if added:
            diff['added'] = sorted(added)
        return diff
