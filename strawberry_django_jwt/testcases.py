import strawberry
from django.contrib.auth.models import AnonymousUser
from django.core.handlers.wsgi import WSGIRequest
from django.test import Client
from django.test import RequestFactory
from django.test import testcases

from .middleware import JSONWebTokenMiddleware
from .settings import jwt_settings
from .shortcuts import get_token


class SchemaRequestFactory(RequestFactory):

    def __init__(self, **defaults):
        super().__init__(**defaults)
        self._schema = strawberry.Schema
        self._middleware = [JSONWebTokenMiddleware]

    def schema(self, **kwargs):
        self._schema = strawberry.Schema(**kwargs)

    def middleware(self, middleware):
        self._middleware = middleware

    def execute(self, query, **options):
        self._schema.middleware = [m() for m in self._middleware]
        return self._schema.execute_sync(query, validate_queries=False, **options)


class JSONWebTokenClient(SchemaRequestFactory, Client):

    def __init__(self, **defaults):
        super().__init__(**defaults)
        self._credentials = {}

    def request(self, **request):
        request = WSGIRequest(self._base_environ(**request))
        request.user = AnonymousUser()
        return request

    def credentials(self, **kwargs):
        self._credentials = kwargs

    def execute(self, query, variables=None, **extra):
        extra.update(self._credentials)
        context = self.post('/', **extra)

        return super().execute(
            query,
            context_value=context,
            variable_values=variables,
        )

    def authenticate(self, user):
        self._credentials = {
            jwt_settings.JWT_AUTH_HEADER_NAME:
            f'{jwt_settings.JWT_AUTH_HEADER_PREFIX} {get_token(user)}',
        }

    def logout(self):
        self._credentials.pop(jwt_settings.JWT_AUTH_HEADER_NAME, None)


class JSONWebTokenTestCase(testcases.TestCase):
    client_class = JSONWebTokenClient
