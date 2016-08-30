# authentication / authorization related error classes


class UserUnknownError(Exception):
    pass


class TokenVersionError(Exception):
    pass


class AuthenticationError(Exception):
    pass


class NotAuthorized(Exception):
    pass
