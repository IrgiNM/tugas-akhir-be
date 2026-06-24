from apscheduler.schedulers.background import BackgroundScheduler
import requests

from .services.watchguard_logs import fetch_logs
from .services.watchguard_get_syslog import fetch_logs_syslogs
from .services.syslog_dataset_service import export_yesterday_syslog_dataset


BASE_URL = "https://tugas-akhir-be-production.up.railway.app"

scheduler_instance = None


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
        print(f"RUNNING {full_url}", flush=True)
        response = requests.get(full_url, timeout=60)
        print(f"STATUS {url}: {response.status_code}", flush=True)
    except Exception as e:
        print(f"ERROR {url}: {str(e)}", flush=True)


def safe_run(job_name, func):
    try:
        print(f"START {job_name}", flush=True)
        result = func()
        print(f"FINISH {job_name}: {result}", flush=True)
    except Exception as e:
        print(f"ERROR {job_name}: {str(e)}", flush=True)


def run_all_jobs():
    print("========================================", flush=True)
    print("SCHEDULER RUNNING", flush=True)
    print("========================================", flush=True)

    # 1. Fetch logs dari API luar
    safe_run("fetch_watchguard_logs", fetch_logs)

    # 2. Fetch logs dari Syslog UPATIK
    safe_run("fetch_syslog_logs", fetch_logs_syslogs)

    # 3. Export dataset CSV
    safe_run("export_syslog_dataset_csv", export_yesterday_syslog_dataset)

    # 4. Top Reports
    print("START top_reports", flush=True)

    for index, url in enumerate(TOP_REPORT_URLS, start=1):
        print(f"TOP REPORT {index}/{len(TOP_REPORT_URLS)}", flush=True)
        call_api(url)

    print("FINISH top_reports", flush=True)

    print("========================================", flush=True)
    print("SCHEDULER FINISH", flush=True)
    print("========================================", flush=True)


def start():
    global scheduler_instance

    if scheduler_instance and scheduler_instance.running:
        print("Scheduler already running...", flush=True)
        return

    scheduler = BackgroundScheduler(timezone="Asia/Jakarta")

    scheduler.add_job(
        run_all_jobs,
        "interval",
        minutes=5,
        id="run_all_jobs_every_5_minutes",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    scheduler.start()
    scheduler_instance = scheduler

    print("Scheduler started, running every 5 minutes...", flush=True)