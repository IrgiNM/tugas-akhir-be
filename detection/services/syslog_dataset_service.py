import csv
import json
from datetime import datetime, date, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from django.conf import settings
from django.utils import timezone

from ..models import SyslogLog, SyslogDataset
from ..utils.vps_storage import upload_file_to_vps


DATE_FIELD_CANDIDATES = [
    "timestamp",
    "log_time",
    "created_at",
    "datetime",
]

FIELD_MAP = {
    "timestamp": ["timestamp", "log_time", "created_at", "datetime"],
    "log_type": ["log_type", "type", "category"],
    "event_type": ["event_type", "event", "event_name"],
    "action": ["action", "disposition"],
    "protocol": ["protocol", "proto"],
    "src_ip": ["src_ip", "source_ip", "client_ip"],
    "src_port": ["src_port", "source_port"],
    "dst_ip": ["dst_ip", "destination_ip", "dest_ip"],
    "dst_port": ["dst_port", "destination_port", "dest_port"],
    "src_country": ["src_country", "source_country"],
    "dst_country": ["dst_country", "destination_country", "dest_country"],
    "policy_name": ["policy_name", "policy"],
    "application": ["application", "app_name", "app"],
    "url": ["url", "domain", "request_url"],
    "url_category": ["url_category", "category_name"],
    "severity": ["severity", "level"],
    "message": ["message", "raw_message", "raw_log", "log"],
}

CSV_HEADERS = [
    "timestamp",
    "date",
    "hour",
    "day_of_week",
    "log_type",
    "event_type",
    "action",
    "protocol",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "src_country",
    "dst_country",
    "policy_name",
    "application",
    "url",
    "url_category",
    "severity",
    "is_blocked",
    "is_allowed",
    "message",
]


BLOCK_ACTIONS = {
    "deny",
    "denied",
    "block",
    "blocked",
    "drop",
    "dropped",
    "reject",
    "rejected",
    "reset",
}

ALLOW_ACTIONS = {
    "allow",
    "allowed",
    "accept",
    "accepted",
    "permit",
    "permitted",
}


def get_model_field_names():
    return [field.name for field in SyslogLog._meta.fields]


def get_available_date_field():
    field_names = get_model_field_names()

    for field in DATE_FIELD_CANDIDATES:
        if field in field_names:
            return field

    raise Exception(
        "Tidak ada field tanggal yang cocok pada model SyslogLog. "
        "Pastikan model punya field timestamp atau created_at."
    )


def parse_target_date(target_date=None):
    if target_date is None:
        return timezone.localdate()

    if isinstance(target_date, date):
        return target_date

    if isinstance(target_date, str):
        return datetime.strptime(target_date, "%Y-%m-%d").date()

    raise ValueError("Format tanggal tidak valid. Gunakan format YYYY-MM-DD.")


def get_date_range(target_date):
    tz = ZoneInfo(getattr(settings, "TIME_ZONE", "Asia/Jakarta"))

    start_date = datetime.combine(target_date, time.min).replace(tzinfo=tz)
    end_date = start_date + timedelta(days=1)

    return start_date, end_date


def get_first_value(obj, field_candidates, default=""):
    for field in field_candidates:
        if hasattr(obj, field):
            value = getattr(obj, field)

            if value is not None and value != "":
                return value

    return default


def clean_value(value):
    if value is None:
        return ""

    if isinstance(value, datetime):
        return timezone.localtime(value).strftime("%Y-%m-%d %H:%M:%S")

    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)

    return str(value)


def get_local_datetime(value):
    if not isinstance(value, datetime):
        return None

    if timezone.is_naive(value):
        value = timezone.make_aware(value)

    return timezone.localtime(value)


def build_csv_row(log):
    timestamp_value = get_first_value(log, FIELD_MAP["timestamp"])
    local_dt = get_local_datetime(timestamp_value)

    action = clean_value(get_first_value(log, FIELD_MAP["action"])).lower()

    is_blocked = 1 if action in BLOCK_ACTIONS else 0
    is_allowed = 1 if action in ALLOW_ACTIONS else 0

    return {
        "timestamp": clean_value(timestamp_value),
        "date": local_dt.strftime("%Y-%m-%d") if local_dt else "",
        "hour": local_dt.hour if local_dt else "",
        "day_of_week": local_dt.strftime("%A") if local_dt else "",
        "log_type": clean_value(get_first_value(log, FIELD_MAP["log_type"])),
        "event_type": clean_value(get_first_value(log, FIELD_MAP["event_type"])),
        "action": clean_value(get_first_value(log, FIELD_MAP["action"])),
        "protocol": clean_value(get_first_value(log, FIELD_MAP["protocol"])),
        "src_ip": clean_value(get_first_value(log, FIELD_MAP["src_ip"])),
        "src_port": clean_value(get_first_value(log, FIELD_MAP["src_port"])),
        "dst_ip": clean_value(get_first_value(log, FIELD_MAP["dst_ip"])),
        "dst_port": clean_value(get_first_value(log, FIELD_MAP["dst_port"])),
        "src_country": clean_value(get_first_value(log, FIELD_MAP["src_country"])),
        "dst_country": clean_value(get_first_value(log, FIELD_MAP["dst_country"])),
        "policy_name": clean_value(get_first_value(log, FIELD_MAP["policy_name"])),
        "application": clean_value(get_first_value(log, FIELD_MAP["application"])),
        "url": clean_value(get_first_value(log, FIELD_MAP["url"])),
        "url_category": clean_value(get_first_value(log, FIELD_MAP["url_category"])),
        "severity": clean_value(get_first_value(log, FIELD_MAP["severity"])),
        "is_blocked": is_blocked,
        "is_allowed": is_allowed,
        "message": clean_value(get_first_value(log, FIELD_MAP["message"])),
    }


def export_syslog_dataset_to_csv(target_date=None, generated_by="manual"):
    target_date = parse_target_date(target_date)
    start_date, end_date = get_date_range(target_date)

    date_field = get_available_date_field()

    queryset = SyslogLog.objects.filter(
        **{
            f"{date_field}__gte": start_date,
            f"{date_field}__lt": end_date,
        }
    ).order_by(date_field, "id")

    dataset_dir = Path(settings.SYSLOG_DATASET_DIR)
    dataset_dir.mkdir(parents=True, exist_ok=True)

    filename = f"syslog_dataset_{target_date.strftime('%Y-%m-%d')}.csv"
    file_path = dataset_dir / filename

    total_rows = 0

    with open(file_path, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)
        writer.writeheader()

        for log in queryset.iterator(chunk_size=1000):
            writer.writerow(build_csv_row(log))
            total_rows += 1

    stat = file_path.stat()

    # Upload file CSV dari Railway ke VPS
    file_url = upload_file_to_vps(str(file_path), filename)

    dataset, created = SyslogDataset.objects.update_or_create(
        dataset_date=target_date,
        defaults={
            "file_name": filename,

            # file_path sekarang kita isi URL file di VPS
            "file_path": file_url,

            "total_rows": total_rows,
            "size_bytes": stat.st_size,
            "size_mb": round(stat.st_size / (1024 * 1024), 2),

            # ubah dari local menjadi vps
            "storage_type": "vps",

            "generated_by": generated_by,
            "status": "success",
        }
    )

    return {
        "id": dataset.id,
        "date": target_date.strftime("%Y-%m-%d"),
        "file_name": filename,

        # URL file yang bisa dibuka/download
        "file_url": file_url,

        # tetap dikirim juga agar kode lama tidak langsung rusak
        "file_path": file_url,

        "total_rows": total_rows,
        "size_bytes": stat.st_size,
        "size_mb": round(stat.st_size / (1024 * 1024), 2),
        "created": created,
    }


def export_today_syslog_dataset():
    return export_syslog_dataset_to_csv(timezone.localdate())


def export_yesterday_syslog_dataset():
    yesterday = timezone.localdate() - timedelta(days=1)
    return export_syslog_dataset_to_csv(
        yesterday,
        generated_by="scheduler"
    )