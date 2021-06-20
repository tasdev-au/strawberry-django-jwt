import strawberry
from strawberry.django.context import StrawberryDjangoContext
from strawberry.types import Info

from ..mixins import RequestInfoMixin
from ..object_types import DeleteType
from ..settings import jwt_settings
from .decorators import ensure_refresh_token
from .object_types import RevokeType
from .shortcuts import get_refresh_token


class Revoke(RequestInfoMixin):
    @strawberry.mutation
    @ensure_refresh_token
    def revoke(self, info: Info, refresh_token: str) -> RevokeType:
        context = info.context
        refresh_token_obj = get_refresh_token(refresh_token, context)
        refresh_token_obj.revoke(context)
        return RevokeType(revoked=refresh_token_obj.revoked)


class DeleteRefreshTokenCookie(RequestInfoMixin):
    @strawberry.mutation
    def delete_cookie(self, info: Info) -> DeleteType:
        context = info.context
        req = context.request \
            if isinstance(context, StrawberryDjangoContext) \
            else context
        req.delete_refresh_token_cookie = (
            jwt_settings.JWT_REFRESH_TOKEN_COOKIE_NAME in req.COOKIES and
            getattr(req, 'jwt_cookie', False)
        )
        return DeleteType(deleted=req.delete_refresh_token_cookie)
