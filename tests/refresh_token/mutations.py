from strawberry_django_jwt.mixins import JSONWebTokenMixin
from strawberry_django_jwt.mixins import RefreshTokenMixin


class Refresh(RefreshTokenMixin, JSONWebTokenMixin):
    pass
