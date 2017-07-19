from aiohttp import web
from aiohttp.log import web_logger
from aiohttp_security import setup as setup_security, authorized_userid, SessionIdentityPolicy, forget, remember
from aiohttp_session import get_session
from aioweb.middleware.csrf import CSRF_SESSION_NAME

from .. import DBAuthorizationPolicy, USER_MODEL, get_user_by_id, REQUEST_KEY
from ..app.models.user import AbstractUser
from aioweb.modules.db import init_db
from aioweb.util import awaitable


async def make_request_user(request):
    identity = await authorized_userid(request)
    if identity:
        try:
            user = get_user_by_id(identity)
            setattr(user, 'is_authenticated', lambda: True)
            setattr(request, 'user', user)
        except USER_MODEL.ModelNotFound:
            setattr(request, 'user', AbstractUser())
    else:
        setattr(request, 'user', AbstractUser())


async def process_auth(request, response):
    if request.get(REQUEST_KEY):
        if request[REQUEST_KEY].get('remember') and request.user.is_authenticated():
            await remember(request, response, request.user.username)
            # response.set_cookie('Csrf-Token', request.csrf_token)
        if request[REQUEST_KEY].get('forget'):
            await forget(request, response)
            session = await get_session(request)
            session.pop(CSRF_SESSION_NAME, None)


async def middleware(app, handler):
    async def middleware_handler(request):
        await make_request_user(request)
        try:
            response = await awaitable(handler(request))
        except web.HTTPException as e:
            await process_auth(request, e)
            raise e
        except Exception as e:
            await process_auth(request, e)
            raise e  # web.HTTPInternalServerError(reason='Unknown error')
        else:
            await process_auth(request, response)
        return response

    return middleware_handler


async def setup(app):
    for requirement in ['db', 'session']:
        if not app.has_module(requirement):
            web_logger.warn("%s module is required for auth module. Skipping" % requirement)

    await init_db(app)
    setup_security(app,
                   SessionIdentityPolicy(),
                   DBAuthorizationPolicy())
