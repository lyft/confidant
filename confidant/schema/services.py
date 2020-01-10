import attr
import toastedmarshmallow
from marshmallow import fields, pre_dump, Schema

from confidant.schema.auto_build_schema import AutobuildSchema
from confidant.schema.blind_credentials import (
    BlindCredentialResponse,
    BlindCredentialResponseSchema,
)
from confidant.schema.credentials import (
    CredentialResponse,
    CredentialResponseSchema,
)
from confidant.utils.dynamodb import encode_last_evaluated_key


@attr.s
class ServiceResponse(object):
    id = attr.ib()
    revision = attr.ib()
    enabled = attr.ib()
    modified_date = attr.ib()
    modified_by = attr.ib()
    account = attr.ib(default=None)
    credentials = attr.ib(default=list)
    blind_credentials = attr.ib(default=list)
    permissions = attr.ib(default=dict)

    @classmethod
    def from_service(
        cls,
        service,
        include_credentials=False,
        include_blind_credentials=False,
    ):
        ret = cls(
            id=service.id,
            account=service.account,
            revision=service.revision,
            enabled=service.enabled,
            modified_date=service.modified_date,
            modified_by=service.modified_by,
        )
        if include_credentials:
            ret.credentials = service.credentials
        if include_blind_credentials:
            ret.blind_credentials = service.blind_credentials
        return ret

    @classmethod
    def from_service_expanded(
        cls,
        service,
        credentials,
        blind_credentials,
        metadata_only=True,
    ):
        ret = cls(
            id=service.id,
            account=service.account,
            revision=service.revision,
            enabled=service.enabled,
            modified_date=service.modified_date,
            modified_by=service.modified_by,
        )
        if metadata_only:
            include_sensitive = False
        else:
            include_sensitive = True
        ret.credentials = [
            CredentialResponse.from_credential(
                credential,
                include_credential_keys=True,
                include_credential_pairs=include_sensitive,
            )
            for credential in credentials
        ]
        ret.blind_credentials = [
            BlindCredentialResponse.from_blind_credential(
                blind_credential,
                include_credential_keys=True,
                include_credential_pairs=include_sensitive,
                include_data_key=include_sensitive,
            )
            for blind_credential in blind_credentials
        ]
        return ret


class ServiceResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = ServiceResponse

    id = fields.Str(required=True)
    account = fields.Str(required=True)
    credentials = fields.List(fields.Str())
    blind_credentials = fields.List(fields.Str())
    revision = fields.Int(required=True)
    enabled = fields.Boolean(required=True)
    modified_date = fields.DateTime(required=True)
    modified_by = fields.Str(required=True)
    permissions = fields.Dict(keys=fields.Str(), values=fields.Boolean())


class ServiceExpandedResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = ServiceResponse

    id = fields.Str(required=True)
    account = fields.Str(required=True)
    credentials = fields.List(fields.Nested(CredentialResponseSchema))
    blind_credentials = fields.List(
        fields.Nested(BlindCredentialResponseSchema)
    )
    revision = fields.Int(required=True)
    enabled = fields.Boolean(required=True)
    modified_date = fields.DateTime(required=True)
    modified_by = fields.Str(required=True)
    permissions = fields.Dict(keys=fields.Str(), values=fields.Boolean())


@attr.s
class ServicesResponse(object):
    services = attr.ib()
    next_page = attr.ib()

    @classmethod
    def from_services(
        cls,
        services,
        next_page=None,
        include_credentials=False,
        include_blind_credentials=False,
    ):
        return cls(
            services=[
                ServiceResponse.from_service(
                    service,
                    include_credentials=include_credentials,
                    include_blind_credentials=include_blind_credentials,
                )
                for service in services
            ],
            next_page=next_page,
        )


class ServicesResponseSchema(Schema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = ServicesResponse

    services = fields.Nested(
        ServiceResponseSchema,
        many=True,
    )
    next_page = fields.Str()

    @pre_dump
    def encode_next_page(self, item):
        item.next_page = encode_last_evaluated_key(item.next_page)
        return item

    @pre_dump
    def sort_services(self, item):
        item.services = sorted(
           item.services,
           key=lambda k: k.id.lower(),
        )
        return item


@attr.s
class RevisionsResponse(object):
    revisions = attr.ib()
    next_page = attr.ib()

    @classmethod
    def from_services(
        cls,
        services,
        include_credentials=False,
        include_blind_credentials=False,
        next_page=None,
    ):
        return cls(
            revisions=[
                ServiceResponse.from_service(
                    service,
                    include_credentials=include_credentials,
                    include_blind_credentials=include_blind_credentials,
                )
                for service in services
            ],
            next_page=next_page,
        )


class RevisionsResponseSchema(Schema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = RevisionsResponse

    revisions = fields.Nested(
        ServiceResponseSchema,
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


service_expanded_response_schema = ServiceExpandedResponseSchema()
services_response_schema = ServicesResponseSchema()
revisions_response_schema = RevisionsResponseSchema()
