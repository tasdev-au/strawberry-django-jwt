import asyncio

from asgiref.sync import sync_to_async
from django.apps import AppConfig


class TestsApp(AppConfig):
    name = "tests"

    def ready(self) -> None:
        from django.core.management import call_command

        loop = asyncio.get_event_loop()
        loop.create_task(sync_to_async(call_command)("migrate"))

        from django.contrib.auth.models import User

        loop.create_task(
            sync_to_async(User.objects.create_superuser)(
                "admin", "admin@admin.com", "admin"
            )
        )
