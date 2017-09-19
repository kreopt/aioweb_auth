import importlib

from aiohttp.log import web_logger
from aiohttp_security import authorized_userid, permits, SessionIdentityPolicy

from aioweb_auth.exceptions import UserNotFoundError, PasswordDoesNotMatchError
from aioweb.conf import settings


def __import_class(path):
    chunks = path.split('.')
    mod = importlib.import_module('.'.join(chunks[:-1]))
    return getattr(mod, chunks[-1])


AUTHORIZATION_POLICY = __import_class(settings.AUTH_AUTHORIZATION_POLICY)

if hasattr(settings, 'AUTH_IDENTITY_POLICY'):
    IDENTITY_POLICY = __import_class(settings.AUTH_IDENTITY_POLICY)
else:
    web_logger.warn("No AUTH_IDENTITY_POLICY set. using SessionIdentityPolicy by default")
    IDENTITY_POLICY = SessionIdentityPolicy


REQUEST_KEY = 'AIOWEB_AUTH'


def __check_request_key(request):
    if not REQUEST_KEY in request or type(request[REQUEST_KEY]) != dict:
        request[REQUEST_KEY] = {}


def remember_user(request, identity):
    __check_request_key(request)
    request[REQUEST_KEY]['remember'] = identity


def forget_user(request):
    __check_request_key(request)
    request[REQUEST_KEY]['forget'] = True
    request['just_logged_out'] = True