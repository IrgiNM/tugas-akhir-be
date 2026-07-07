# import os
# from django.apps import AppConfig

# class DetectionConfig(AppConfig):
#     default_auto_field = 'django.db.models.BigAutoField'
#     name = 'detection'

#     def ready(self):

#         if os.environ.get('RUN_MAIN') == 'true':

#             from .scheduler import start
#             start()



from django.apps import AppConfig
import os


    class DetectionConfig(AppConfig):
        default_auto_field = "django.db.models.BigAutoField"
        name = "detection"

        def ready(self):
            # Scheduler hanya jalan kalau env ini aktif
            if os.environ.get("RUN_SCHEDULER") != "true":
                print("Scheduler disabled. Set RUN_SCHEDULER=true to enable.", flush=True)
                return

            try:
                from .scheduler import start
                start()
            except Exception as e:
                print(f"Scheduler failed to start: {e}", flush=True)