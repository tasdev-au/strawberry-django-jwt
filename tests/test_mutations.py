import strawberry
import strawberry_django_jwt.mutations
from django.contrib.auth import get_user_model

from . import mixins
from .testcases import CookieTestCase
from .testcases import SchemaTestCase


class TokenAuthTests(mixins.TokenAuthMixin, SchemaTestCase):
    query = '''
    mutation TokenAuth($username: String!, $password: String!) {
      tokenAuth(username: $username, password: $password) {
        token
        payload {
            username
        }
        refreshExpiresIn
      }
    }'''

    @strawberry.type
    class Mutation:
        token_auth = strawberry_django_jwt.mutations.ObtainJSONWebToken.obtain


class VerifyTests(mixins.VerifyMixin, SchemaTestCase):
    query = '''
    mutation VerifyToken($token: String!) {
      verifyToken(token: $token) {
        payload {
            username
        }
      }
    }'''

    @strawberry.type
    class Mutation:
        verify_token = strawberry_django_jwt.mutations.Verify.verify


class RefreshTests(mixins.RefreshMixin, SchemaTestCase):
    query = '''
    mutation RefreshToken($token: String) {
      refreshToken(token: $token) {
        token
        payload {
            username
            origIat
            exp
        }
        refreshExpiresIn
      }
    }'''

    @strawberry.type
    class Mutation:
        refresh_token = strawberry_django_jwt.mutations.Refresh.refresh


class CookieTokenAuthTests(mixins.CookieTokenAuthMixin, CookieTestCase):
    query = f'''
    mutation TokenAuth($username: String!, $password: String!) {{
      tokenAuth(username: $username, password: $password) {{
        token
        payload {{
            {get_user_model().USERNAME_FIELD}
        }}
        refreshExpiresIn
      }}
    }}'''

    @strawberry.type
    class Mutation:
        token_auth = strawberry_django_jwt.mutations.ObtainJSONWebToken.obtain


class CookieRefreshTests(mixins.CookieRefreshMixin, CookieTestCase):
    query = '''
    mutation {
      refreshToken {
        token
        payload {
            username
        }
        refreshExpiresIn
      }
    }'''

    @strawberry.type
    class Mutation:
        refresh_token = strawberry_django_jwt.mutations.Refresh.refresh


class DeleteCookieTests(mixins.DeleteCookieMixin, CookieTestCase):
    query = '''
    mutation {
      deleteCookie {
        deleted
      }
    }'''

    @strawberry.type
    class Mutation:
        delete_cookie = strawberry_django_jwt.mutations.DeleteJSONWebTokenCookie.delete_cookie
