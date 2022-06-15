from defweb.errors.base import DefWebException


class MiddlewareException(DefWebException):
    pass


class MiddlewareInitError(MiddlewareException):
    pass
