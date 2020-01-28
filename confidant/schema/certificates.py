import attr
import toastedmarshmallow
from marshmallow import fields

from confidant.schema.auto_build_schema import AutobuildSchema


@attr.s
class CertificateResponse(object):
    id = attr.ib()
    certificate = attr.ib()
    certificate_chain = attr.ib()
    key = attr.ib(default=None)


class CertificateExpandedResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = CertificateResponse

    certificate = fields.Str(required=True)
    certificate_chain = fields.Str(required=True)
    key = fields.Str()


certificate_expanded_response_schema = CertificateExpandedResponseSchema()
