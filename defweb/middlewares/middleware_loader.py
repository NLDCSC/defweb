from defweb.middlewares import *

_local_vars = locals()


class MiddlewareNotFound(Exception):
    pass


class MiddlewareLoader(object):
    def __init__(self):

        mods = [
            {middleware: _local_vars[middleware]}
            for middleware in _local_vars
            if not middleware.startswith("_")
            and not middleware.startswith("MiddlewareLoader")
            and not middleware.startswith("MiddlewareNotFound")
        ]

        middlewares = {}

        for each in mods:
            for key, val in each.items():
                middleware_class = [run for run in dir(val) if run.endswith("Middleware")]
                middlewares[key] = getattr(val, middleware_class[0])

        self.middleware_choises = dict(middlewares)

    def load_middleware(self, name: str):
        """
        Method to load the requested middleware
        """
        try:
            middleware = self.middleware_choises[name]
            return middleware
        except KeyError:
            raise MiddlewareNotFound("Cannot find the requested runner!")
