import importlib

from aiohttp import web
from aiohttp.log import web_logger
from aiohttp_security.abc import AbstractAuthorizationPolicy
from aiohttp_session import get_session
from aioweb.core import Model
from aioweb.util import awaitable
from orator.exceptions.orm import ModelNotFound
from passlib.hash import sha256_crypt

from aioweb_auth.exceptions import UserNotFoundError, PasswordDoesNotMatchError
from .app.models.user import AbstractUser

from aioweb.conf import settings

chunks = settings.AUTH_USER_MODEL.split('.')

mod = importlib.import_module('.'.join(chunks[:-1]))
USER_MODEL = getattr(mod, chunks[-1])

REQUEST_KEY = 'AIOWEB_AUTH'


async def get_user_by_name(login, force_db=False):
    if login is None:
        return AbstractUser()
    try:
        # return USER_MODEL.where('email', login).or_where('phone', login).first_or_fail()
        return await awaitable(USER_MODEL().get_by_username(login, force_db=force_db))
    except ModelNotFound:
        return AbstractUser()


async def get_user_by_id(user_id, force_db=False):
    # return USER_MODEL.where('id', id).first_or_fail()
    return await awaitable(USER_MODEL().get_by_id(user_id, force_db=force_db))


class DBAuthorizationPolicy(AbstractAuthorizationPolicy):
    async def authorized_userid(self, identity):
        # TODO: check cache
        user = await get_user_by_name(identity)
        if user.is_authenticated():
            return user.id
        else:
            return None

    async def permits(self, identity, permission, context=None):
        if identity is None:
            return False
        return await USER_MODEL().can(permission)


class AbstractUser(object):

    @property
    def id(self):
        return None

    def is_authenticated(self):
        return False

class BaseUserFactory(Model):
    async def authenticate(self, user, **kwargs):
        raise AuthError()

    async def get_by_id(self, user_id):
        return None

    async def get_by_name(self, username):
        return None

async def get_session_user(request):
    session = await get_session(request)
    user_id = session.get('user_id')
    if user_id:
        return await UserFactory().get_by_id(user_id)
    else:
        return AbstractUser()


def wrap_authenticated_user(user):
    if type(user) != AbstractUser:
        setattr(user, 'is_authenticated', lambda: True)


def attach_user_to_request(request, user):
    setattr(request, 'user', wrap_authenticated_user(user))


def check_request_key(request):
    if not REQUEST_KEY in request or type(request[REQUEST_KEY]) != dict:
        request[REQUEST_KEY] = {}


async def remember_user(request):
    check_request_key(request)
    request[REQUEST_KEY]['remember'] = True


async def forget_user(request):
    check_request_key(request)
    request[REQUEST_KEY]['forget'] = True
    request['just_logged_out'] = True