import attr
import toastedmarshmallow
from marshmallow import fields, pre_dump, Schema

from confidant.schema.auto_build_schema import AutobuildSchema
from confidant.utils.dynamodb import encode_last_evaluated_key


@attr.s
class CredentialResponse(object):
    id = attr.ib()
    name = attr.ib()
    revision = attr.ib()
    enabled = attr.ib()
    modified_date = attr.ib()
    modified_by = attr.ib()
    documentation = attr.ib(default=None)
    metadata = attr.ib(default=dict)
    credential_keys = attr.ib(default=list)
    credential_pairs = attr.ib(default=dict)
    permissions = attr.ib(default=dict)
    tags = attr.ib(default=list)
    last_rotation_date = attr.ib(default=None)
    next_rotation_date = attr.ib(default=None)

    @classmethod
    def from_credential(
        cls,
        credential,
        include_credential_keys=False,
        include_credential_pairs=False,
    ):
        ret = cls(
            id=credential.id,
            name=credential.name,
            metadata=credential.metadata,
            revision=credential.revision,
            enabled=credential.enabled,
            documentation=credential.documentation,
            modified_date=credential.modified_date,
            modified_by=credential.modified_by,
            tags=credential.tags,
            last_rotation_date=credential.last_rotation_date,
            next_rotation_date=credential.next_rotation_date,
        )
        if include_credential_keys:
            ret.credential_keys = credential.credential_keys
        if include_credential_pairs:
            ret.credential_pairs = credential.decrypted_credential_pairs
        return ret


class CredentialResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = CredentialResponse

    id = fields.Str(required=True)
    name = fields.Str(required=True)
    credential_keys = fields.List(fields.Str())
    credential_pairs = fields.Dict(keys=fields.Raw(), values=fields.Raw())
    metadata = fields.Dict(keys=fields.Raw(), values=fields.Raw())
    revision = fields.Int(required=True)
    enabled = fields.Boolean(required=True)
    documentation = fields.Str(required=True)
    modified_date = fields.DateTime(required=True)
    modified_by = fields.Str(required=True)
    permissions = fields.Dict(keys=fields.Str(), values=fields.Boolean())
    tags = fields.List(fields.Str())
    last_rotation_date = fields.DateTime()
    next_rotation_date = fields.DateTime()


@attr.s
class CredentialsResponse(object):
    credentials = attr.ib()
    next_page = attr.ib()

    @classmethod
    def from_credentials(
        cls,
        credentials,
        next_page=None,
        include_credential_keys=False,
        include_credential_pairs=False,
    ):
        return cls(
            credentials=[
                CredentialResponse.from_credential(
                    credential,
                    include_credential_keys,
                    include_credential_pairs,
                )
                for credential in credentials
            ],
            next_page=next_page,
        )


class CredentialsResponseSchema(Schema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = CredentialsResponse

    credentials = fields.Nested(
        CredentialResponseSchema,
        many=True,
    )
    next_page = fields.Str()

    @pre_dump
    def encode_next_page(self, item):
        item.next_page = encode_last_evaluated_key(item.next_page)
        return item

    @pre_dump
    def sort_credentials(self, item):
        item.credentials = sorted(
           item.credentials,
           key=lambda k: k.name.lower(),
        )
        return item


@attr.s
class RevisionsResponse(object):
    revisions = attr.ib()
    next_page = attr.ib()

    @classmethod
    def from_credentials(
        cls,
        credentials,
        next_page=None,
        include_credential_keys=False,
        include_credential_pairs=False,
    ):
        return cls(
            revisions=[
                CredentialResponse.from_credential(
                    credential,
                    include_credential_keys,
                    include_credential_pairs,
                )
                for credential in credentials
            ],
            next_page=next_page,
        )


class RevisionsResponseSchema(Schema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = RevisionsResponse

    revisions = fields.Nested(
        CredentialResponseSchema,
        many=True,
    )
    next_page = fields.Str()

    @pre_dump
    def encode_next_page(self, item):
        item.next_page = encode_last_evaluated_key(item.next_page)
        return item

    @pre_dump
    def sort_revisions(self, item):
        item.revisions = sorted(
           item.revisions,
           key=lambda k: k.revision,
        )
        return item


credential_response_schema = CredentialResponseSchema()
credentials_response_schema = CredentialsResponseSchema()
revisions_response_schema = RevisionsResponseSchema()
