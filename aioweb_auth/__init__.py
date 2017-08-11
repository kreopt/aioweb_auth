import importlib

from aiohttp import web
from aiohttp.log import web_logger
from aiohttp_security.abc import AbstractAuthorizationPolicy
from aioweb.util import awaitable
from orator.exceptions.orm import ModelNotFound
from passlib.hash import sha256_crypt

from .app.models.user import User, AbstractUser

try:
    from aioweb.conf import settings

    chunks = settings.AUTH_USER_MODEL.split('.')

    mod = importlib.import_module('.'.join(chunks[:-1]))
    USER_MODEL = getattr(mod, chunks[-1])
except (ImportError, AttributeError) as e:
    web_logger.debug("failed to import user model")
    USER_MODEL = User

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
        return USER_MODEL.can(permission)


class AuthError(Exception):
    def __init__(self, reason, *args) -> None:
        super().__init__(reason, *args)
        self.reason = reason

    def __str__(self):
        return self.reason


class AuthValidator(object):
    def __init__(self):
        self.reason = "check failed"

    def validate(self, user):
        return False


async def authenticate_user(request, user, remember=False, validators=tuple()):
    for validator in validators:
        if not validator.validate(user):
            raise AuthError(validator.reason)
    setattr(user, 'is_authenticated', lambda: True)
    request['just_authenticated'] = True
    setattr(request, 'user', user)
    if remember:
        await remember_user(request)

    return user


async def authenticate(request, username, password, remember=False, validators=tuple()):
    user = await get_user_by_name(username, force_db=True)
    if user.is_authenticated():
        if sha256_crypt.verify(password, user.password):
            return await authenticate_user(request, user, remember=remember, validators=validators)
        else:
            setattr(request, 'user', AbstractUser())
            raise AuthError("Некорректный пароль")
    else:
        setattr(request, 'user', AbstractUser())
        raise AuthError("Пользователь не найден")


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


async def redirect_authenticated(request):
    if request.user.is_authenticated() and not request.is_ajax():
        redirect_url = request.query.get('redirect_to')
        if not redirect_url:
            redirect_url = getattr(settings, 'AUTH_PRIVATE_URL', '/')
        raise web.HTTPFound(redirect_url)


def auth_error_response(controller, reason, detail=None):
    if controller.request.is_ajax():
        return web.HTTPForbidden(reason=reason)
    else:
        controller.flash['AUTH_ERROR'] = detail if detail else reason
        return web.HTTPFound(controller.path_for('index'))


async def auth_success_response(controller):
    if not controller.request.is_ajax():
        await redirect_authenticated(controller.request)
    else:
        return {'id': controller.request.user.id, 'token': controller.request.csrf_token}
