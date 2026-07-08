from django.apps import AppConfig
import os


class DetectionConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "detection"

    def ready(self):
        if os.environ.get("RUN_SCHEDULER", "false").lower() != "true":
            return

        try:
            from .scheduler import start
            start()
        except Exception:
            pass