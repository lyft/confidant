from pynamodb.attributes import UnicodeSetAttribute


class NonNullUnicodeSetAttribute(UnicodeSetAttribute):
    def __get__(self, instance, value):
        '''
        Override UnicodeSetAttribute's __get__ method to return a set, rather
        than None if the attribute isn't set.
        '''
        if instance:
            # Get the attribute. If the object doesn't have the attribute,
            # ensure we return a set.
            _value = instance.attribute_values.get(self.attr_name, set())
            # Attribute is assigned to None, return a set instead.
            if _value is None:
                _value = set()
            return _value
        else:
            return self
