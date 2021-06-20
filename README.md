# Strawberry Django JWT

[![PyPI - Downloads](https://img.shields.io/pypi/dm/strawberry-django-jwt?style=for-the-badge)](https://pypi.org/project/strawberry-django-jwt/)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/m/KundaPanda/strawberry-django-jwt?style=for-the-badge)](https://github.com/KundaPanda/strawberry-django-jwt/graphs/commit-activity)
![GitHub last commit](https://img.shields.io/github/last-commit/KundaPanda/strawberry-django-jwt?style=for-the-badge)

[JSON Web Token](https://jwt.io/>) authentication
for [Strawberry Django GraphQL](https://strawberry.rocks/docs/integrations/django)

---

## Disclaimer

This project is a forked version of [Django GraphQL JWT](https://github.com/flavors/django-graphql-jwt) that substitutes [Graphene](https://graphene-python.org/) GraphQL backend for [Strawberry](https://strawberry.rocks/)

---

## Installation

1. Install last stable version from Pypi:

   ```shell
   pip install strawberry-django-jwt
   ```

2. Add `AuthenticationMiddleware` middleware to your **MIDDLEWARE** settings:

   ```python
   MIDDLEWARE = [
       ...,
       'django.contrib.auth.middleware.AuthenticationMiddleware',
       ...,
   ]
   ```

3. Add `JSONWebTokenMiddleware` middleware to your **STRAWBERRY** schema definition:

   ```python
   from strawberry_django_jwt.middleware import JSONWebTokenMiddleware
   from strawberry import Schema

   schema = Schema(...)
   schema.middleware.extend([
        JSONWebTokenMiddleware(),
   ])
   ```

4. Add `JSONWebTokenBackend` backend to your **AUTHENTICATION_BACKENDS**:

   ```python
   AUTHENTICATION_BACKENDS = [
       'strawberry_django_jwt.backends.JSONWebTokenBackend',
       'django.contrib.auth.backends.ModelBackend',
   ]
   ```

5. Add _django-graphql-jwt_ mutations to the root schema:

   ```python
   import strawberry
   import strawberry_django_jwt.mutations as jwt_mutations

   @strawberry.type
   class Mutation:
       token_auth = jwt_mutations.ObtainJSONWebToken.obtain
       verify_token = jwt_mutations.Verify.verify
       refresh_token = jwt_mutations.Refresh.refresh
       delete_token_cookie = jwt_mutations.DeleteJSONWebTokenCookie.delete_cookie


   schema = strawberry.Schema(mutation=Mutation, query=...)
   ```

---

## Documentation

_Work in Progress_
