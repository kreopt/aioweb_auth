from aiohttp import web
from aiohttp_security import authorized_userid

from aioweb.core.controller.decorators import before_action


def auth_or_403(redirect_to):
    async def decorated(self):
        user_id = await authorized_userid(self.request)
        if not user_id:
            if redirect_to:
                raise web.HTTPFound(redirect_to)
            else:
                raise web.HTTPForbidden(reason='Unauthorized')

    return decorated


def authenticated(redirect_to=None, only=tuple(), exclude=()):
    return before_action(auth_or_403(redirect_to), only, exclude)


def check_logged(redirect_to=None):
    async def fn(request, controller, actionName):
        user_id = await authorized_userid(request)
        if not user_id:
            if not request.is_ajax() and redirect_to:
                raise web.HTTPFound(redirect_to)
            else:
                raise web.HTTPForbidden(reason='Unauthorized')

    return fn
