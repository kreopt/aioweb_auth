from aiohttp import web
from aioweb.conf import settings

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
