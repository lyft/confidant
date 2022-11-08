import json
from datetime import datetime, timedelta

from pynamodb.models import Model
from pynamodb.attributes import (
    UnicodeAttribute,
    NumberAttribute,
    BooleanAttribute,
    UTCDateTimeAttribute,
    BinaryAttribute,
    JSONAttribute,
    ListAttribute
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


class ArchiveDataTypeDateIndex(GlobalSecondaryIndex):
    class Meta:
        projection = AllProjection()
        read_capacity_units = 10
        write_capacity_units = 10
    data_type = UnicodeAttribute(hash_key=True)
    modified_date = UTCDateTimeAttribute(range_key=True)


class CredentialBase(Model):
    id = UnicodeAttribute(hash_key=True)
    revision = NumberAttribute()
    data_type = UnicodeAttribute()
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
    tags = ListAttribute(default=list)
    last_decrypted_date = UTCDateTimeAttribute(null=True)
    last_rotation_date = UTCDateTimeAttribute(null=True)


class Credential(CredentialBase):
    class Meta:
        table_name = settings.DYNAMODB_TABLE
        if settings.DYNAMODB_URL:
            host = settings.DYNAMODB_URL
        region = settings.AWS_DEFAULT_REGION
        connection_cls = DDBConnection
        session_cls = DDBSession

    data_type_date_index = DataTypeDateIndex()

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
        if set(self.tags) != set(other_cred.tags):
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
        if set(old.tags) != set(new.tags):
            diff['tags'] = {
                'added': list(set(new.tags) - set(old.tags)),
                'removed': list(set(old.tags) - set(new.tags)),
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
        # Some credentials never need to be rotated
        if self.exempt_from_rotation:
            return None

        # If a credential has never been rotated or been decrypted,
        # immediately rotate
        if self.last_rotation_date is None:
            return datetime.now()

        if (self.last_decrypted_date and
                self.last_decrypted_date > self.last_rotation_date):
            return self.last_decrypted_date

        days = settings.MAXIMUM_ROTATION_DAYS
        for tag in self.tags:
            rotation_days = settings.ROTATION_DAYS_CONFIG.get(tag)
            if rotation_days is None:
                continue
            if days is None or rotation_days < days:
                days = rotation_days
        return self.last_rotation_date + timedelta(days=days)

    @property
    def exempt_from_rotation(self):
        """
        Credentials with certain tags can be exempt from rotation
        """
        return len(set(self.tags) & set(settings.TAGS_EXCLUDING_ROTATION)) > 0

    @property
    def decrypted_credential_pairs(self):
        return self._get_decrypted_credential_pairs()

    @classmethod
    def from_archive_credential(cls, archive_credential):
        return Credential(
            id=archive_credential.id,
            revision=archive_credential.revision,
            data_type=archive_credential.data_type,
            name=archive_credential.name,
            credential_pairs=archive_credential.credential_pairs,
            enabled=archive_credential.enabled,
            data_key=archive_credential.data_key,
            cipher_version=archive_credential.cipher_version,
            metadata=archive_credential.metadata,
            modified_date=archive_credential.modified_date,
            modified_by=archive_credential.modified_by,
            documentation=archive_credential.documentation,
            tags=archive_credential.tags,
            last_decrypted_date=archive_credential.last_decrypted_date,
            last_rotation_date=archive_credential.last_rotation_date,
        )


class CredentialArchive(CredentialBase):
    class Meta:
        table_name = settings.DYNAMODB_TABLE_ARCHIVE
        if settings.DYNAMODB_URL:
            host = settings.DYNAMODB_URL
        region = settings.AWS_DEFAULT_REGION
        connection_cls = DDBConnection
        session_cls = DDBSession

    archive_date = UTCDateTimeAttribute(default=datetime.now)
    data_type_date_index = ArchiveDataTypeDateIndex()

    @classmethod
    def from_credential(cls, credential):
        return CredentialArchive(
            id=credential.id,
            revision=credential.revision,
            data_type=credential.data_type,
            name=credential.name,
            credential_pairs=credential.credential_pairs,
            enabled=credential.enabled,
            data_key=credential.data_key,
            cipher_version=credential.cipher_version,
            metadata=credential.metadata,
            modified_date=credential.modified_date,
            modified_by=credential.modified_by,
            documentation=credential.documentation,
            tags=credential.tags,
            last_decrypted_date=credential.last_decrypted_date,
            last_rotation_date=credential.last_rotation_date,
        )
