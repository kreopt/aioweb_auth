import aioweb.core
from aiohttp import web
from aioweb.conf import settings
from aioweb.core.controller.decorators import default_layout, content_type
from aioweb.middleware.csrf.decorators import csrf_exempt
from aioweb.util import import_controller, awaitable

from aioweb_auth import authenticate, AuthError, forget_user, redirect_authenticated, auth_error_response, \
    auth_success_response
from aioweb_auth.util.validators import sub_email_or_phone


@default_layout('base.html')
class AuthController(aioweb.core.Controller):

    @content_type(only=['text/html'])
    async def index(self):
        await redirect_authenticated(self.request)
        if hasattr(settings, 'AUTH_INDEX_HANDLER'):
            ctrl, action = getattr(settings, 'AUTH_INDEX_HANDLER').split('#')
            ctrl_class, ctrl_class_name = import_controller(ctrl)
            hdlr = getattr(ctrl_class, action)
            return await awaitable(hdlr(self))
        else:
            raise web.HTTPNotFound()

    @csrf_exempt
    async def login(self):
        data = await self.request.post()
        try:
            username = sub_email_or_phone(data.get('username', ''))
            if username:
                await authenticate(self.request, username, data.get('password', ''), remember=True)
            else:
                raise auth_error_response(self, 'Invalid username', detail='Такого пользователя не существует')
        except AuthError as e:
            raise auth_error_response(self, str(e))

        if hasattr(settings, 'AUTH_LOGIN_HANDLER'):
            ctrl, action = getattr(settings, 'AUTH_LOGIN_HANDLER').split('#')
            ctrl_class, ctrl_class_name = import_controller(ctrl)
            hdlr = getattr(ctrl_class, action)
            res = await awaitable(hdlr(self))
            if res:
                return res

        return await auth_success_response(self)

    async def logout(self):
        res = {}
        if hasattr(settings, 'AUTH_LOGOUT_HANDLER'):
            ctrl, action = getattr(settings, 'AUTH_LOGOUT_HANDLER').split('#')
            ctrl_class, ctrl_class_name = import_controller(ctrl)
            hdlr = getattr(ctrl_class, action)
            res = await awaitable(hdlr(self))

        await forget_user(self.request)
        if not self.request.is_ajax():
            raise web.HTTPFound(getattr(settings, 'AUTH_GUEST_URL', '/'))
        else:
            return res
