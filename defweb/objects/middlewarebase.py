from abc import ABC, abstractmethod


class DefWebMiddlewareBase(ABC):
    def __init__(self, data):
        self.data = data

    @abstractmethod
    def initialize(self) -> bool:
        return True

    @abstractmethod
    def execute(self) -> bool:
        return True
