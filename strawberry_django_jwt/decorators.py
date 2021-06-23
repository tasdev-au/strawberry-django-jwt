import inspect
from calendar import timegm
from datetime import datetime
from functools import wraps

import strawberry
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.middleware.csrf import rotate_token
from django.utils.translation import gettext as _

from . import exceptions
from . import signals
from .refresh_token.shortcuts import create_refresh_token
from .refresh_token.shortcuts import refresh_token_lazy
from .settings import jwt_settings
from .utils import delete_cookie
from .utils import get_context
from .utils import maybe_thenable
from .utils import set_cookie

__all__ = [
    'user_passes_test',
    'login_required',
    'staff_member_required',
    'superuser_required',
    'permission_required',
    'refresh_expiration',
    'token_auth',
    'csrf_rotation',
    'setup_jwt_cookie',
    'jwt_cookie',
    'ensure_token',
    'dispose_extra_kwargs',
    'login_field'
]


def login_required(target):
    get_result = next((name
                       for (name, _)
                       in inspect.getmembers(target, inspect.ismethod)
                       if name == "get_result"), None)
    if get_result is not None:
        target.get_result = login_required(target.get_result)
        return target
    return user_passes_test(lambda u: u.is_authenticated)(target)


def context(f):
    def decorator(func):
        def wrapper(*args, **kwargs):
            info = kwargs.get("info")
            ctx = get_context(info)
            return func(ctx, *args, **kwargs)

        return wrapper

    return decorator


def user_passes_test(test_func, exc=exceptions.PermissionDenied):
    def decorator(f):
        @wraps(f)
        @context(f)
        def wrapper(context, *args, **kwargs):
            if context and test_func(context.user):
                return dispose_extra_kwargs(f)(*args, **kwargs)
            raise exc

        return wrapper

    return decorator


staff_member_required = user_passes_test(lambda u: u.is_staff)
superuser_required = user_passes_test(lambda u: u.is_superuser)


def login_field(fn=None):
    return strawberry.field(login_required(fn))


def permission_required(perm):
    def check_perms(user):
        if isinstance(perm, str):
            perms = (perm,)
        else:
            perms = perm
        return user.has_perms(perms)

    return user_passes_test(check_perms)


def on_token_auth_resolve(values):
    info, user, payload = values
    ctx = get_context(info)
    payload.payload = jwt_settings.JWT_PAYLOAD_HANDLER(user, ctx)
    payload.token = jwt_settings.JWT_ENCODE_HANDLER(payload.payload, ctx)

    if jwt_settings.JWT_LONG_RUNNING_REFRESH_TOKEN:
        if getattr(ctx, 'jwt_cookie', False):
            ctx.jwt_refresh_token = create_refresh_token(user)
            payload.refresh_token = ctx.jwt_refresh_token.get_token()
        else:
            payload.refresh_token = refresh_token_lazy(user)

    return payload


def token_auth(f):
    @wraps(f)
    @setup_jwt_cookie
    @csrf_rotation
    @refresh_expiration
    def wrapper(cls, info, password, **kwargs):
        context = info.context
        context._jwt_token_auth = True
        username = kwargs.get(get_user_model().USERNAME_FIELD)

        user = authenticate(
            request=context,
            username=username,
            password=password,
        )
        if user is None:
            raise exceptions.JSONWebTokenError(
                _('Please enter valid credentials'),
            )

        if hasattr(context, 'user'):
            context.user = user

        result = f(cls, info, **kwargs)
        signals.token_issued.send(sender=cls, request=context, user=user)
        return maybe_thenable((info, user, result), on_token_auth_resolve)

    return wrapper


def refresh_expiration(f):
    @wraps(f)
    def wrapper(cls, *args, **kwargs):
        def on_resolve(payload):
            payload.refresh_expires_in = (
                    timegm(datetime.utcnow().utctimetuple()) +
                    jwt_settings.JWT_REFRESH_EXPIRATION_DELTA.total_seconds()
            )
            return payload

        result = f(cls, *args, **kwargs)
        return maybe_thenable(result, on_resolve)

    return wrapper


def csrf_rotation(f):
    @wraps(f)
    def wrapper(cls, info, *args, **kwargs):
        result = f(cls, info, **kwargs)

        if jwt_settings.JWT_CSRF_ROTATION:
            rotate_token(info.context)
        return result

    return wrapper


def setup_jwt_cookie(f):
    @wraps(f)
    def wrapper(cls, info, *args, **kwargs):
        result = f(cls, info, **kwargs)
        ctx = get_context(info)
        if getattr(ctx, 'jwt_cookie', False):
            ctx.jwt_token = result.token
        return result

    return wrapper


def apply_status(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        response = view_func(request, *args, **kwargs)


def jwt_cookie(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        request.jwt_cookie = True
        response = view_func(request, *args, **kwargs)

        if hasattr(request, 'jwt_token'):
            expires = datetime.utcnow() + jwt_settings.JWT_EXPIRATION_DELTA

            set_cookie(
                response,
                jwt_settings.JWT_COOKIE_NAME,
                request.jwt_token,
                expires=expires,
            )
            if hasattr(request, 'jwt_refresh_token'):
                refresh_token = request.jwt_refresh_token
                expires = refresh_token.created + \
                          jwt_settings.JWT_REFRESH_EXPIRATION_DELTA

                set_cookie(
                    response,
                    jwt_settings.JWT_REFRESH_TOKEN_COOKIE_NAME,
                    refresh_token.token,
                    expires=expires,
                )

        if hasattr(request, 'delete_jwt_cookie'):
            delete_cookie(response, jwt_settings.JWT_COOKIE_NAME)

        if hasattr(request, 'delete_refresh_token_cookie'):
            delete_cookie(response, jwt_settings.JWT_REFRESH_TOKEN_COOKIE_NAME)

        return response

    return wrapped_view


def ensure_token(f):
    @wraps(f)
    def wrapper(cls, info, token=None, *args, **kwargs):
        if token is None:
            cookies = get_context(info).COOKIES
            token = cookies.get(jwt_settings.JWT_COOKIE_NAME)

            if token is None:
                raise exceptions.JSONWebTokenError(_('Token is required'))
        return f(cls, info, token, *args, **kwargs)

    return wrapper


def dispose_extra_kwargs(fn):
    @wraps(fn)
    def wrapper(src, *args_, **kwargs_):
        root = {}
        if src:
            args_ = args_[1:]
        present = inspect.signature(fn).parameters.keys()
        for key, val in kwargs_.items():
            if key not in present:
                root[key] = val
        passed_kwargs = {k: v for k, v in kwargs_.items() if k in present}
        if src:
            return fn(src, root, *args_, **passed_kwargs)
        return fn(root, *args_, **passed_kwargs)

    return wrapper


def pass_info(f):
    @wraps(f)
    def wrapper(self, *args_, **kwargs_):
        info = kwargs_.pop("info", None)
        if info is None and len(args_) > 0:
            info = args_[0]
        return f(self, info, *args_, **kwargs_)

    return wrapper
