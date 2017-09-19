from aiohttp import web
from aiohttp.log import web_logger
from aiohttp_security import setup as setup_security, authorized_userid, SessionIdentityPolicy, forget, remember

from .. import REQUEST_KEY, IDENTITY_POLICY, AUTHORIZATION_POLICY
from aioweb.util import awaitable

async def process_auth(request, response):
    if request.get(REQUEST_KEY):
        identity = request[REQUEST_KEY].get('remember')
        if identity:
            await remember(request, response, identity)
        if request[REQUEST_KEY].get('forget'):
            await forget(request, response)


async def middleware(app, handler):
    async def middleware_handler(request):
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
    setup_security(app,
                   IDENTITY_POLICY(),
                   AUTHORIZATION_POLICY())
