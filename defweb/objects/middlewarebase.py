from abc import ABC, abstractmethod

from defweb.errors.middleware_errors import MiddlewareInitError


class DefWebMiddlewareBase(ABC):

    __protocol__ = "general"
    __hook__ = "printers"
    __weight__ = 100

    def __init__(self, data=None, **kwargs):
        self.data = data
        self.kwargs = kwargs

        if self.kwargs:
            for each in self.kwargs:
                setattr(self, each, self.kwargs[each])

        if not self.initialize():
            raise MiddlewareInitError(
                f"{self.__class__.__name__} could not initialize successfully"
            )

    @abstractmethod
    def initialize(self) -> bool:
        """
        Method to do additional processing on the data or class before the self.execute method is called

        Should return True when successful, False on failure.
        """
        return True

    @abstractmethod
    def execute(self) -> bool:
        """
        Primary method to do all processing on the self.data

        Should return True when data should be passed down the middlewares, False will stop the processing and
        will drop the data.

        All imports required to execute this middleware should be imported in this method
        """
        return True
