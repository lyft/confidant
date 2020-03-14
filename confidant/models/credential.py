import json
from datetime import datetime, timedelta

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

from confidant import settings
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
    credential_pairs = UnicodeAttribute()
    enabled = BooleanAttribute(default=True)
    data_key = BinaryAttribute()
    # TODO: add cipher_type
    cipher_version = NumberAttribute(null=True)
    metadata = JSONAttribute(default=dict, null=True)
    modified_date = UTCDateTimeAttribute(default=datetime.now)
    modified_by = UnicodeAttribute()
    documentation = UnicodeAttribute(null=True)

    # Classification info (eg: FINANCIALLY_SENSITIVE)
    category = UnicodeAttribute(null=True)
    last_decrypted_date = UTCDateTimeAttribute(null=True)
    last_rotation_date = UTCDateTimeAttribute(null=True)

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
        if self.category != other_cred.category:
            return False
        return True

    def diff(self, other_cred):
        if self.revision == other_cred.revision:
            return {}
        elif self.revision > other_cred.revision:
            old = other_cred
            new = self
        else:
            old = self
            new = other_cred
        diff = {}
        if old.name != new.name:
            diff['name'] = {'added': new.name, 'removed': old.name}
        old_cred_pairs = old.decrypted_credential_pairs
        new_cred_pairs = new.decrypted_credential_pairs
        if old_cred_pairs != new_cred_pairs:
            diff['credential_pairs'] = self._diff_dict(
                old_cred_pairs,
                new_cred_pairs
            )
        if old.metadata != new.metadata:
            diff['metadata'] = self._diff_dict(old.metadata, new.metadata)
        if old.enabled != new.enabled:
            diff['enabled'] = {'added': new.enabled, 'removed': old.enabled}
        if old.documentation != new.documentation:
            diff['documentation'] = {
                'added': new.documentation,
                'removed': old.documentation
            }
        if old.category != new.category:
            diff['category'] = {
                'added': new.category,
                'removed': old.category
            }
        if old.last_rotation_date != new.last_rotation_date:
            diff['last_rotation_date'] = {
                'added': new.last_rotation_date,
                'removed': old.last_rotation_date
            }

        diff['modified_by'] = {
            'added': new.modified_by,
            'removed': old.modified_by,
        }
        diff['modified_date'] = {
            'added': new.modified_date,
            'removed': old.modified_date,
        }
        return diff

    def _diff_dict(self, old, new):
        diff = {}
        removed = []
        added = []
        for key, value in old.items():
            if key not in new:
                removed.append(key)
            elif old[key] != new[key]:
                # modified is indicated by a remove and add
                removed.append(key)
                added.append(key)
        for key, value in new.items():
            if key not in old:
                added.append(key)
        if removed:
            diff['removed'] = sorted(removed)
        if added:
            diff['added'] = sorted(added)
        return diff

    @property
    def credential_keys(self):
        return list(self.decrypted_credential_pairs)

    def _get_decrypted_credential_pairs(self):
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

    @property
    def next_rotation_date(self):
        """
        Return when a credential needs to be rotated for security purposes.
        """
        if not self.requires_rotation or self.rotation_frequency is None:
            return None

        # If a credential has never been rotated or been decrypted,
        # immediately rotate
        if self.last_rotation_date is None:
            return datetime.utcnow()

        if self.last_decrypted_date and \
                self.last_decrypted_date > self.last_rotation_date:
            return datetime.utcnow()

        return self.last_rotation_date + timedelta(days=self.rotation_frequency)

    @property
    def rotation_frequency(self):
        """
        Return how frequently a credential needs to be rotated
        Return None if category is not in CREDENTIAL_ROTATION_DAYS config
        """
        return settings.CREDENTIAL_ROTATION_DAYS.get(self.category)

    @property
    def requires_rotation(self):
        """
        Some credentials need to be periodically rotated
        """
        return self.category == settings.FINANCIALLY_SENSITIVE

    @property
    def decrypted_credential_pairs(self):
        return(self._get_decrypted_credential_pairs())
