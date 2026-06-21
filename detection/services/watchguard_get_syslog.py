import requests
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from ..models import SyslogLog
from .watchguard_parser import parse_watchguard_log


SYSLOG_RANGE_URL = "https://syslogwatchguard.polindra.ac.id/api/logs/range"


def normalize_api_response(response_json):
    if isinstance(response_json, dict):
        return response_json.get("data", [])

    if isinstance(response_json, list):
        return response_json

    return []


def fetch_logs_syslogs(date_from=None, date_to=None):
    print("Mengambil logs dari syslog UPATIK...")

    token = settings.WATCHGUARD_BEARER_TOKEN

    if not token:
        print("WATCHGUARD_BEARER_TOKEN belum diatur")
        return {
            "created": 0,
            "skipped": 0,
            "error": 1,
            "total_from_api": 0,
            "message": "WATCHGUARD_BEARER_TOKEN belum diatur",
        }

    yesterday = timezone.localdate() - timedelta(days=1)

    date_from = date_from or yesterday.isoformat()
    date_to = date_to or yesterday.isoformat()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "Django-Backend-Syslog-Fetcher/1.0",
    }

    params = {
        "from": date_from,
        "to": date_to,
    }

    try:
        response = requests.get(
            SYSLOG_RANGE_URL,
            headers=headers,
            params=params,
            timeout=60,
        )
    except requests.exceptions.RequestException as e:
        print("REQUEST ERROR:", str(e))
        return {
            "created": 0,
            "skipped": 0,
            "error": 1,
            "total_from_api": 0,
            "from": date_from,
            "to": date_to,
            "message": "Gagal koneksi ke API syslog UPATIK",
            "detail": str(e),
        }

    print("SYSLOG URL:", response.url)
    print("SYSLOG STATUS:", response.status_code)

    content_type = response.headers.get("Content-Type", "")
    print("CONTENT TYPE:", content_type)

    if "text/html" in content_type or "Just a moment" in response.text:
        print("API terkena Cloudflare Challenge. Harus bypass /api/* di Cloudflare.")
        return {
            "created": 0,
            "skipped": 0,
            "error": 1,
            "total_from_api": 0,
            "from": date_from,
            "to": date_to,
            "message": "Cloudflare challenge detected",
        }

    if response.status_code != 200:
        print("SYSLOG RESPONSE:", response.text)
        return {
            "created": 0,
            "skipped": 0,
            "error": 1,
            "total_from_api": 0,
            "from": date_from,
            "to": date_to,
            "message": f"API syslog error {response.status_code}",
            "detail": response.text,
        }

    try:
        response_json = response.json()
    except Exception as e:
        print("Response bukan JSON:", str(e))
        print(response.text[:500])
        return {
            "created": 0,
            "skipped": 0,
            "error": 1,
            "total_from_api": 0,
            "from": date_from,
            "to": date_to,
            "message": "Response bukan JSON",
        }

    raw_logs = normalize_api_response(response_json)

    created = 0
    skipped = 0
    error = 0

    existing_raw_logs = set(
        SyslogLog.objects
        .filter(raw_log__in=raw_logs)
        .values_list("raw_log", flat=True)
    )

    objects = []

    for raw_log in raw_logs:
        if not raw_log:
            continue

        if raw_log in existing_raw_logs:
            skipped += 1
            continue

        try:
            parsed_data = parse_watchguard_log(raw_log)
            objects.append(SyslogLog(**parsed_data))
            created += 1
        except Exception as e:
            print("PARSE ERROR:", str(e))
            print("RAW LOG:", raw_log)
            error += 1

    if objects:
        SyslogLog.objects.bulk_create(
            objects,
            batch_size=1000,
            ignore_conflicts=True,
        )

    result = {
        "created": created,
        "skipped": skipped,
        "error": error,
        "total_from_api": len(raw_logs),
        "from": date_from,
        "to": date_to,
    }

    print("SYSLOG RESULT:", result)
    return result