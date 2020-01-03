from marshmallow import post_load, Schema


class StrictSchema(Schema):
    """
    Simple subclass of Schema that sets the strict setting to true. This means
    validation errors will raise an exception.
    """
    class Meta:
        strict = True


class AutobuildSchema(StrictSchema):
    """
    By default, calling load on a marshmallow schema will return a dictionary of
    field names mapped to their deserialized values. In order to deserialize to
    an object the official recommendation is to create a function decorated with
    a "post_load" function. [1]

    Since we always want to deserialize to an object, adding this post_load
    function would lead to a lot of boilerplate. This class serves to reduce
    that boilerplate.

    To use, subclass and set assign a _class_to_load class member variable to
    the class you want an instance of. That class will be constructed with
    keyword arguments resulting from the schema load.

    [1] https://marshmallow.readthedocs.org/en/latest/quickstart.html#deserializing-to-objects  # noqa:E501

    Example::

        from marshmallow import fields

        class Foo(object):

           def __init__(self, bar=None):
               self.bar = bar

        class FooSchema(AutobuildSchema):

           _class_to_load = Foo

           bar = fields.String()

        schema = FooSchema()
        foo = schema.load({'foo': 'bar'}).data

        print foo.__class__.__name__
        Foo
    """

    _class_to_load = None

    @post_load
    def build_object(self, data):
        if self._class_to_load is None:
            raise NotImplementedError('Subclass did not set "_class_to_load"')

        return self._class_to_load(**data)
