import attr
import toastedmarshmallow
from marshmallow import fields

from confidant.schema.auto_build_schema import AutobuildSchema


@attr.s
class CertificateAuthorityResponse(object):
    ca = attr.ib()
    certificate = attr.ib()
    certificate_chain = attr.ib()
    tags = attr.ib()


@attr.s
class CertificateAuthoritiesResponse(object):
    cas = attr.ib()

    @classmethod
    def from_cas(cls, cas):
        return cls(
            cas=[
                CertificateAuthorityResponse(
                    ca=ca['ca'],
                    certificate=ca['certificate'],
                    certificate_chain=ca['certificate_chain'],
                    tags=ca['tags'])
                for ca in cas
            ],
        )


class CertificateAuthorityResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = CertificateAuthorityResponse

    ca = fields.Str(required=True)
    certificate = fields.Str(required=True)
    certificate_chain = fields.Str(required=True)
    tags = fields.Dict(keys=fields.Str(), values=fields.Str())


class CertificateAuthoritiesResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = CertificateAuthoritiesResponse

    cas = fields.Nested(CertificateAuthorityResponseSchema, many=True)


@attr.s
class CertificateResponse(object):
    certificate = attr.ib()
    certificate_chain = attr.ib()
    key = attr.ib(default=None)


class CertificateResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = CertificateResponse

    certificate = fields.Str(required=True)
    certificate_chain = fields.Str(required=True)


class CertificateExpandedResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = CertificateResponse

    certificate = fields.Str(required=True)
    certificate_chain = fields.Str(required=True)
    key = fields.Str()


certificate_response_schema = CertificateResponseSchema()
certificate_authority_response_schema = CertificateAuthorityResponseSchema()
certificate_authorities_response_schema = CertificateAuthoritiesResponseSchema()
certificate_expanded_response_schema = CertificateExpandedResponseSchema()
