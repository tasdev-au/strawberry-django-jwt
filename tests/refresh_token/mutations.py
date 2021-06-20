from strawberry_django_jwt.mixins import RefreshTokenMixin, JSONWebTokenMixin


class Refresh(RefreshTokenMixin, JSONWebTokenMixin):
    pass
