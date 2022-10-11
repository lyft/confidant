import attr
import toastedmarshmallow
from marshmallow import fields

from confidant.schema.auto_build_schema import AutobuildSchema


@attr.s
class JWTResponse(object):
    token = attr.ib()


class JWTResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = JWTResponse
    token = fields.Str(required=True)


jwt_response_schema = JWTResponseSchema()
