from datetime import timedelta

from apscheduler.schedulers.background import BackgroundScheduler
import requests

from django.utils import timezone

from .services.watchguard_logs import fetch_logs
from .services.watchguard_get_syslog import fetch_logs_syslogs
from .services.syslog_dataset_service import export_today_syslog_dataset


BASE_URL = "https://tugas-akhir-be-production.up.railway.app"


TOP_REPORT_URLS = [
    "/detection/top-blocked-countries/",
    "/detection/top-blocked-advanced-malware-apt/",
    "/detection/top-blocked-botnet-sites/",
    "/detection/top-blocked-clients/",
    "/detection/top-blocked-destinations/",
    "/detection/top-blocked-url-categories/",
    "/detection/top-blocked-applications/",
    "/detection/top-blocked-application-categories/",
    "/detection/top-blocked-protocols/",
    "/detection/top-blocked-attacks/",
    "/detection/top-blocked-malware/",

    "/detection/top-countries/",
    "/detection/top-zero-day-malware-apt/",
    "/detection/top-clients/",
    "/detection/top-domains/",
    "/detection/top-url-categories/",
    "/detection/top-destinations/",
    "/detection/top-applications/",
    "/detection/top-application-categories/",
    "/detection/top-protocols/",
]


def call_api(url):
    full_url = f"{BASE_URL}{url}"

    try:
        print(f"RUNNING {full_url}")
        response = requests.get(full_url, timeout=60)
        print(f"STATUS: {response.status_code}")
    except Exception as e:
        print(f"ERROR: {str(e)}")


def call_all_top_reports():
    print("START generate top reports")

    for url in TOP_REPORT_URLS:
        call_api(url)

    print("FINISH generate top reports")


def start():
    scheduler = BackgroundScheduler(timezone="Asia/Jakarta")

    # =========================
    # LANGSUNG FETCH SAAT SERVER START
    # supaya aplikasi tidak kosong setelah deploy/restart
    # =========================
    scheduler.add_job(
        fetch_logs_syslogs,
        "date",
        run_date=timezone.now() + timedelta(seconds=10),
        id="fetch_syslog_logs_now",
        replace_existing=True,
    )

    scheduler.add_job(
        export_today_syslog_dataset,
        "date",
        run_date=timezone.now() + timedelta(minutes=2),
        id="export_syslog_dataset_now",
        replace_existing=True,
    )

    # =========================
    # FETCH SYSLOG HARI INI SETIAP 3 JAM
    # jam 00:05, 03:05, 06:05, dst
    # =========================
    scheduler.add_job(
        fetch_logs_syslogs,
        "cron",
        hour="0,6,12,18",
        minute=5,
        id="fetch_syslog_logs_every_3_hours",
        replace_existing=True,
    )

    # =========================
    # EXPORT CSV HARI INI SETIAP 3 JAM
    # setelah fetch selesai
    # =========================
    scheduler.add_job(
        export_today_syslog_dataset,
        "cron",
        hour="0,6,12,18",
        minute=15,
        id="export_syslog_dataset_every_3_hours",
        replace_existing=True,
    )

    # =========================
    # TOP REPORTS SETIAP 3 JAM
    # setelah fetch dan export
    # =========================
    scheduler.add_job(
        call_all_top_reports,
        "cron",
        hour="0,6,12,18",
        minute=25,
        id="top_reports_every_3_hours",
        replace_existing=True,
    )

    # =========================
    # FETCH FINAL SEBELUM GANTI HARI
    # supaya data hari ini paling lengkap
    # =========================
    scheduler.add_job(
        fetch_logs_syslogs,
        "cron",
        hour=23,
        minute=45,
        id="fetch_syslog_logs_final_today",
        replace_existing=True,
    )

    scheduler.add_job(
        export_today_syslog_dataset,
        "cron",
        hour=23,
        minute=55,
        id="export_syslog_dataset_final_today",
        replace_existing=True,
    )

    scheduler.start()
    print("Scheduler started...")