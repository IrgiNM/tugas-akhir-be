from apscheduler.schedulers.background import BackgroundScheduler
import requests

from .services.watchguard_logs import fetch_logs
from .services.watchguard_get_syslog import fetch_logs_syslogs


BASE_URL = "http://127.0.0.1:8000"


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

# def start():
#     scheduler = BackgroundScheduler(timezone="Asia/Jakarta")

#     # ambil sekarang sekali
#     scheduler.add_job(
#         fetch_logs,
#         "date",
#         id="fetch_watchguard_logs_now",
#         replace_existing=True,
#     )

#     scheduler.add_job(
#         fetch_logs_syslogs,
#         "date",
#         id="fetch_syslog_logs_now",
#         replace_existing=True,
#     )

#     scheduler.start()
#     print("Scheduler started and fetch logs running now...")

def start():
    scheduler = BackgroundScheduler(timezone="Asia/Jakarta")

    # =========================
    # FETCH LOGS DARI API LUAR
    # jalan sehari sekali jam 00:10
    # =========================
    scheduler.add_job(
        fetch_logs,
        "cron",
        hour=0,
        minute=10,
        id="fetch_watchguard_logs",
        replace_existing=True,
    )
    
    # =========================
    # FETCH LOGS DARI SYSLOG UPATIK
    # jalan sehari sekali jam 00:10
    # =========================
    scheduler.add_job(
        fetch_logs_syslogs,
        "cron",
        hour=0,
        minute=10,
        id="fetch_syslog_logs",
        replace_existing=True,
    )

    # =========================
    # TOP REPORTS
    # jalan sehari sekali jam 00:30
    # =========================
    for index, url in enumerate(TOP_REPORT_URLS):
        scheduler.add_job(
            call_api,
            "cron",
            hour=0,
            minute=30 + index,
            args=[url],
            id=f"top_report_{index}",
            replace_existing=True,
        )

    scheduler.start()
    print("Scheduler started...")





# from apscheduler.schedulers.background import BackgroundScheduler

# from .services.watchguard_get_syslog import fetch_logs_syslogs


# def start():
#     scheduler = BackgroundScheduler(timezone="Asia/Jakarta")

#     scheduler.add_job(
#         fetch_logs_syslogs,
#         "date",
#         id="fetch_syslog_logs_now",
#         replace_existing=True,
#     )

#     scheduler.start()
#     print("Scheduler started and fetch syslog running now...")