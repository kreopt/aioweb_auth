import re
from aiohttp import web
from aiohttp_session import get_session
from aioweb.conf import settings
from aioweb.core import Model
from aioweb.middleware.csrf import CSRF_SESSION_NAME
from aioweb_auth import remember_user
from aioweb_auth.abc import AbstractUserFactory, AbstractAuthorizationPolicy, AbstractIdentityPolicy
from aiohttp_security import SessionIdentityPolicy

from passlib.handlers.sha2_crypt import sha256_crypt

from aioweb_auth.exceptions import UserNotFoundError, PasswordDoesNotMatchError, AuthError


EMAIL_REGEX = '''(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'''


class IdentityPolicy(SessionIdentityPolicy):
    async def forget(self, request, response):
        super().forget(request, response)
        session = await get_session(request)
        session.pop(CSRF_SESSION_NAME, None)


class AuthPolicy(AbstractAuthorizationPolicy):
    async def permits(self, identity, permission, context=None):
        return True

    async def authorized_userid(self, identity):
        return identity


class UserFactory(AbstractUserFactory):
    async def get_by_id(self, user_id):
        return await self.request.app.dbc.first("""select * from users where id=:user_id""", {'user_id': user_id})

    async def get_by_name(self, username):
        return await self.request.app.dbc.first("""select * from users where email=:username""", {'username': username})


async def authenticate(request, username, password, should_remember=False):
    user = await UserFactory(request).get_by_name(username)
    if user.is_authenticated():
        if sha256_crypt.verify(password, user.password):
            if should_remember:
                await remember_user(request, user.id)
            return user
        else:
            raise PasswordDoesNotMatchError("Некорректный пароль")
    else:
        raise UserNotFoundError("Пользователь не найден")
