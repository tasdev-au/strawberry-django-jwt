import functools
import inspect
from calendar import timegm
from datetime import datetime
from inspect import isawaitable
from typing import List, Optional, Union, Any

import django
import jwt
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.utils.translation import gettext as _
from strawberry.django.context import StrawberryDjangoContext

from . import exceptions
from . import object_types
from .settings import jwt_settings


def strip_kwargs(fn, strip: List[str]):
    def decorate(*args, **kwargs):
        return fn(args, **{k: v for k, v in kwargs.items() if k not in strip})

    return decorate


def jwt_payload(user, context=None):
    username = user.get_username()

    if hasattr(username, 'pk'):
        username = username.pk

    exp = datetime.utcnow() + jwt_settings.JWT_EXPIRATION_DELTA

    payload = {
        user.USERNAME_FIELD: username,
        'exp': timegm(exp.utctimetuple()),
    }

    if jwt_settings.JWT_ALLOW_REFRESH:
        payload['origIat'] = timegm(datetime.utcnow().utctimetuple())

    if jwt_settings.JWT_AUDIENCE is not None:
        payload['aud'] = jwt_settings.JWT_AUDIENCE

    if jwt_settings.JWT_ISSUER is not None:
        payload['iss'] = jwt_settings.JWT_ISSUER

    return object_types.TokenPayloadType(**payload)


def jwt_encode(payload: object_types.TokenPayloadType, context=None) -> str:
    return jwt.encode(
        payload.__dict__,
        jwt_settings.JWT_PRIVATE_KEY or jwt_settings.JWT_SECRET_KEY,
        jwt_settings.JWT_ALGORITHM,
    )


def jwt_decode(token: str, context=None) -> object_types.TokenPayloadType:
    return object_types.TokenPayloadType(**jwt.decode(
        token,
        jwt_settings.JWT_PUBLIC_KEY or jwt_settings.JWT_SECRET_KEY,
        options={
            'verify_exp': jwt_settings.JWT_VERIFY_EXPIRATION,
            'verify_aud': jwt_settings.JWT_AUDIENCE is not None,
            'verify_signature': jwt_settings.JWT_VERIFY,
        },
        leeway=jwt_settings.JWT_LEEWAY,
        audience=jwt_settings.JWT_AUDIENCE,
        issuer=jwt_settings.JWT_ISSUER,
        algorithms=[jwt_settings.JWT_ALGORITHM],
    ))


def get_http_authorization(context):
    req = get_context(context)
    auth = req.META.get(jwt_settings.JWT_AUTH_HEADER_NAME, '').split()
    prefix = jwt_settings.JWT_AUTH_HEADER_PREFIX

    if len(auth) != 2 or auth[0].lower() != prefix.lower():
        return req.COOKIES.get(jwt_settings.JWT_COOKIE_NAME)
    return auth[1]


def get_token_argument(request, **kwargs):
    if jwt_settings.JWT_ALLOW_ARGUMENT:
        input_fields = kwargs.get('input')

        if isinstance(input_fields, dict):
            kwargs = input_fields

        return kwargs.get(jwt_settings.JWT_ARGUMENT_NAME)
    return None


# def get_token_argument(field_node, variable_values, **kwargs):
#     if jwt_settings.JWT_ALLOW_ARGUMENT:
#         if field_node.arguments is not None and len(field_node.arguments) > 0:
#             for arg in field_node.arguments:
#                 if arg.name.value == jwt_settings.JWT_ARGUMENT_NAME:
#                     if 'value' not in arg.value.keys:
#                         return variable_values.get(arg.value.name.value)
#                     return arg.value.value
#
#     return None


def get_credentials(request, **kwargs):
    return (get_token_argument(request, **kwargs) or
            get_http_authorization(request))


def get_payload(token, context=None):
    try:
        payload = jwt_settings.JWT_DECODE_HANDLER(token, context)
    except jwt.ExpiredSignatureError:
        raise exceptions.JSONWebTokenExpired()
    except jwt.DecodeError:
        raise exceptions.JSONWebTokenError(_('Error decoding signature'))
    except jwt.InvalidTokenError:
        raise exceptions.JSONWebTokenError(_('Invalid token'))
    return payload


def get_user_by_natural_key(username):
    user_model = get_user_model()
    try:
        return user_model._default_manager.get_by_natural_key(username)
    except user_model.DoesNotExist:
        return None


def get_user_by_payload(payload):
    username = jwt_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER(payload)

    if not username:
        raise exceptions.JSONWebTokenError(_('Invalid payload'))

    user = jwt_settings.JWT_GET_USER_BY_NATURAL_KEY_HANDLER(username)

    if user is not None and not getattr(user, 'is_active', True):
        raise exceptions.JSONWebTokenError(_('User is disabled'))
    return user


def refresh_has_expired(orig_iat, context=None):
    exp = orig_iat + jwt_settings.JWT_REFRESH_EXPIRATION_DELTA.total_seconds()
    return timegm(datetime.utcnow().utctimetuple()) > exp


def set_cookie(response, key, value, expires):
    kwargs = {
        'expires': expires,
        'httponly': True,
        'secure': jwt_settings.JWT_COOKIE_SECURE,
        'path': jwt_settings.JWT_COOKIE_PATH,
        'domain': jwt_settings.JWT_COOKIE_DOMAIN,
    }
    if django.VERSION >= (2, 1):
        kwargs['samesite'] = jwt_settings.JWT_COOKIE_SAMESITE

    response.set_cookie(key, value, **kwargs)


def delete_cookie(response, key):
    response.delete_cookie(
        key,
        path=jwt_settings.JWT_COOKIE_PATH,
        domain=jwt_settings.JWT_COOKIE_DOMAIN,
    )


def await_and_execute(obj, on_resolve):
    async def build_resolve_async():
        return on_resolve(await obj)

    return build_resolve_async()


def maybe_thenable(obj, on_resolve):
    """
    Execute a on_resolve function once the thenable is resolved,
    returning the same type of object inputted.
    If the object is not thenable, it should return on_resolve(obj)
    """
    if isawaitable(obj):
        return await_and_execute(obj, on_resolve)

    # If it's not awaitable, return the function executed over the object
    return on_resolve(obj)


def get_context(info: Any) -> Optional[Union[HttpRequest, HttpRequest]]:
    if info is None:
        return None
    if isinstance(info, StrawberryDjangoContext):
        return info.request
    if issubclass(type(info), HttpRequest):
        return info
    ctx = info.context
    if isinstance(ctx, StrawberryDjangoContext):
        return ctx.request
    return ctx


def get_class_that_defined_method(meth):
    if isinstance(meth, functools.partial):
        return get_class_that_defined_method(meth.func)
    if inspect.ismethod(meth) or (
            inspect.isbuiltin(meth)
            and getattr(meth, '__self__', None) is not None and getattr(meth.__self__, '__class__', None)):
        for cls in inspect.getmro(meth.__self__.__class__):
            if meth.__name__ in cls.__dict__:
                return cls
        meth = getattr(meth, '__func__', meth)  # fallback to __qualname__ parsing
    if inspect.isfunction(meth):
        cls = getattr(inspect.getmodule(meth),
                      meth.__qualname__.split('.<locals>', 1)[0].rsplit('.', 1)[0],
                      None)
        if isinstance(cls, type):
            return cls
    return getattr(meth, '__objclass__', None)  # handle special descriptor objects
