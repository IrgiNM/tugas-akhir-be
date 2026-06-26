from apscheduler.schedulers.background import BackgroundScheduler
import requests

from .services.watchguard_logs import fetch_logs
from .services.watchguard_get_syslog import fetch_logs_syslogs
from .services.syslog_dataset_service import export_today_syslog_dataset


BASE_URL = "https://tugas-akhir-be-production.up.railway.app"


TOP_REPORT_URLS = [
    # SECURITY
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

    # EXECUTIVE
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
    # FETCH LOGS WATCHGUARD
    # jalan setiap hari jam 23:15
    # =========================
    scheduler.add_job(
        fetch_logs,
        "cron",
        hour=23,
        minute=15,
        id="fetch_watchguard_logs",
        replace_existing=True,
    )

    # =========================
    # FETCH LOGS SYSLOG UPATIK
    # jalan setiap hari jam 23:25
    # mengambil data HARI INI
    # =========================
    scheduler.add_job(
        fetch_logs_syslogs,
        "cron",
        hour=23,
        minute=25,
        id="fetch_syslog_logs",
        replace_existing=True,
    )

    # =========================
    # EXPORT DATASET SYSLOG CSV
    # jalan setiap hari jam 23:45
    # export data HARI INI
    # =========================
    scheduler.add_job(
        export_today_syslog_dataset,
        "cron",
        hour=23,
        minute=45,
        id="export_syslog_dataset_csv",
        replace_existing=True,
    )

    # =========================
    # TOP REPORTS
    # jalan setiap hari jam 23:50
    # setelah fetch dan export selesai
    # =========================
    scheduler.add_job(
        call_all_top_reports,
        "cron",
        hour=23,
        minute=50,
        id="top_reports_all",
        replace_existing=True,
    )

    scheduler.start()
    print("Scheduler started...")