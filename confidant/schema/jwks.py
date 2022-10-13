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


@attr.s
class JWKSListResponse(object):
    keys = attr.ib()


@attr.s
class JWKSResponse(object):
    kty = attr.ib()
    kid = attr.ib()
    n = attr.ib()
    e = attr.ib()


class JWKSResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = JWKSResponse

    kty = fields.Str(required=True)
    kid = fields.Str(required=True)
    n = fields.Str(required=True)
    e = fields.Str(required=True)
    alg = fields.Str(required=True)


class JWKSListResponseSchema(AutobuildSchema):
    class Meta:
        jit = toastedmarshmallow.Jit

    _class_to_load = JWKSListResponse
    keys = fields.List(fields.Nested(JWKSResponseSchema))


jwt_response_schema = JWTResponseSchema()
jwks_list_response_schema = JWKSListResponseSchema()
