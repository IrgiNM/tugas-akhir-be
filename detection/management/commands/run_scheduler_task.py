from django.core.management.base import BaseCommand

from detection.services.watchguard_get_syslog import fetch_logs_syslogs
from detection.services.syslog_dataset_service import export_today_syslog_dataset
from detection.scheduler import call_all_top_reports


class Command(BaseCommand):
    help = "Run scheduled detection tasks manually or from cron job."

    def add_arguments(self, parser):
        parser.add_argument(
            "task",
            choices=[
                "fetch_syslog",
                "export_dataset",
                "top_reports",
                "all",
            ],
        )

    def handle(self, *args, **options):
        task = options["task"]

        if task in ["fetch_syslog", "all"]:
            self.stdout.write("Running fetch syslog logs...")
            fetch_logs_syslogs()
            self.stdout.write(self.style.SUCCESS("Fetch syslog finished."))

        if task in ["export_dataset", "all"]:
            self.stdout.write("Running export today syslog dataset...")
            export_today_syslog_dataset()
            self.stdout.write(self.style.SUCCESS("Export dataset finished."))

        if task in ["top_reports", "all"]:
            self.stdout.write("Running top reports...")
            call_all_top_reports()
            self.stdout.write(self.style.SUCCESS("Top reports finished."))