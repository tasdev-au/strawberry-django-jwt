import mock
import strawberry.django
import strawberry_django_jwt.mutations
from django.contrib.auth import get_user_model
from django_mock_queries.query import MockModel  # type: ignore
from django_mock_queries.query import MockSet  # type: ignore
from strawberry.django import auto
from strawberry.django import mutations
from strawberry_django_jwt.decorators import login_required
from strawberry_django_jwt.settings import jwt_settings

from . import mixins
from .models import MyTestModel
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
    query = f'''
    mutation {{
      refreshToken {{
        token
        payload {{
            {get_user_model().USERNAME_FIELD}
        }}
        refreshExpiresIn
      }}
    }}'''

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


@strawberry.django.type(MyTestModel)
class MyTestType:
    test: auto


@strawberry.django.input(MyTestModel)
class MyTestInput:
    test: auto


class MutationFieldTests(SchemaTestCase):
    query = '''
    mutation testCreate {
      testCreate(data: {test: "test"}) {
        test
      }
    }'''

    qs = MockSet(model=MyTestModel)
    objects = mock.patch("tests.models.MyTestModel.objects", qs)

    @strawberry.type
    class Mutation:
        test_create: MyTestType = login_required(mutations.create(MyTestInput))

    @objects
    def test_create_field_unauthorized(self):
        self.qs.add(
            MockModel(name="test")
        )

        response = self.execute()

        self.assertIs(len(response.errors), 1)
        self.assertIsNone(response.data)

    @objects
    def test_create_field(self):
        self.qs.add(
            MockModel(test="test123")
        )

        headers = {
            jwt_settings.JWT_AUTH_HEADER_NAME:
                f'{jwt_settings.JWT_AUTH_HEADER_PREFIX} {self.token}',
        }

        response = self.client.execute(self.query, **headers)

        data = response.data.get("testCreate")

        self.assertIsNone(response.errors)
        self.assertEqual(data["test"], "test")
