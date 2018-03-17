import sys
import logging
from flask.ext.script import Command

from confidant.app import app
from confidant.models.blind_credential import BlindCredential

import json
import six
from pynamodb.attributes import Attribute, UnicodeAttribute, UnicodeSetAttribute
from pynamodb.constants import STRING_SET
from pynamodb.models import Model


app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.INFO)


class SetMixin(object):
    """
    Adds (de)serialization methods for sets
    """
    def serialize(self, value):
        """
        Serializes a set

        Because dynamodb doesn't store empty attributes,
        empty sets return None
        """
        if value is not None:
            try:
                iter(value)
            except TypeError:
                value = [value]
            if len(value):
                return [json.dumps(val) for val in sorted(value)]
        return None

    def deserialize(self, value):
        """
        Deserializes a set
        """
        if value and len(value):
            return set([json.loads(val) for val in value])

class NewUnicodeSetAttribute(SetMixin, Attribute):
    """
    A unicode set
    """
    attr_type = STRING_SET
    null = True

    def element_serialize(self, value):
        """
        This serializes unicode / strings out as unicode strings.
        It does not touch the value if it is already a unicode str
        :param value:
        :return:
        """
        if isinstance(value, six.text_type):
            return value
        return six.u(str(value))

    def element_deserialize(self, value):
        return value

    def serialize(self, value):
        if value is not None:
            try:
                iter(value)
            except TypeError:
                value = [value]
            if len(value):
                return [self.element_serialize(val) for val in sorted(value)]
        return None

    def deserialize(self, value):
        if value and len(value):
            return set([self.element_deserialize(val) for val in value])


class GeneralCredentialModel(Model):
    class Meta(BlindCredential.Meta):
        pass

    id = UnicodeAttribute(hash_key=True)
    credential_keys = NewUnicodeSetAttribute(default=set([]), null=True)
    credentials = NewUnicodeSetAttribute(default=set(), null=True)
    blind_credentials = NewUnicodeSetAttribute(default=set(), null=True)


class MigrateSetAttribute(Command):

    def is_old_unicode_set(self, values):
        return sum([x.startswith('"') for x in values]) > 0

    def run(self):
        total = 0
        fail = 0
        app.logger.info('Migrating UnicodeSetAttribute in BlindCredential')
        for cred in BlindCredential.data_type_date_index.query(
                'blind-credential'):
            cred.save()
            if self.is_old_unicode_set(GeneralCredentialModel.get(cred.id)):
                fail += 1
            total += 1
        print("Fail: {}, Total: {}".format(fail, total))
