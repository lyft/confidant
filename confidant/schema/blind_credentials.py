import attr
import toastedmarshmallow
from marshmallow import fields

from confidant.schema.auto_build_schema import AutobuildSchema


@attr.s
class BlindCredentialResponse(object):
    id = attr.ib()
    name = attr.ib()
    cipher_version = attr.ib()
    cipher_type = attr.ib()
    revision = attr.ib()
    enabled = attr.ib()
    documentation = attr.ib()
    modified_date = attr.ib()
    modified_by = attr.ib()
    metadata = attr.ib(default=dict)
    credential_keys = attr.ib(default=list)
    credential_pairs = attr.ib(default=dict)
    data_key = attr.ib(default=dict)

    @classmethod
    def from_blind_credential(
        cls,
        credential,
        include_credential_keys=False,
        include_credential_pairs=False,
        include_data_key=False,
    ):
        ret = cls(
            id=credential.id,
            name=credential.name,
            cipher_version=credential.cipher_version,
            cipher_type=credential.cipher_type,
            metadata=credential.metadata,
            revision=credential.revision,
            enabled=credential.enabled,
            documentation=credential.documentation,
            modified_date=credential.modified_date,
            modified_by=credential.modified_by,
        )
        if include_credential_keys:
            ret.credential_keys = credential.credential_keys
        if include_credential_pairs:
            ret.credential_pairs = credential.credential_pairs
        if include_data_key:
            ret.data_key = credential.data_key
        return ret


class BlindCredentialResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = BlindCredentialResponse

    id = fields.Str(required=True)
    name = fields.Str(required=True)
    credential_keys = fields.List(fields.Str())
    credential_pairs = fields.Dict(keys=fields.Raw(), values=fields.Raw())
    data_key = fields.Dict(keys=fields.Raw(), values=fields.Raw())
    cipher_type = fields.Str(required=True)
    cipher_version = fields.Int(required=True)
    metadata = fields.Dict(keys=fields.Raw(), values=fields.Raw())
    revision = fields.Int(required=True)
    enabled = fields.Boolean(required=True)
    modified_date = fields.DateTime(required=True)
    modified_by = fields.Str(required=True)
    documentation = fields.Str()


blind_credential_response_schema = BlindCredentialResponseSchema()
