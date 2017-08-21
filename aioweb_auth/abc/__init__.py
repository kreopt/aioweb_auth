import abc

from aiohttp_security import permits
from aiohttp_security.abc import AbstractAuthorizationPolicy, AbstractIdentityPolicy


class AbstractUserFactory(metaclass=abc.ABCMeta):

    def __init__(self, request):
        self.request = request

    @abc.abstractmethod
    async def get_by_id(self, user_id):
        pass