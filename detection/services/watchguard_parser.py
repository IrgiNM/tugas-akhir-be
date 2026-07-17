import re
from django.utils import timezone
from django.utils.dateparse import parse_datetime


def make_aware_if_naive(dt):
    if dt and timezone.is_naive(dt):
        return timezone.make_aware(dt, timezone.get_current_timezone())
    return dt


def parse_key_value(text):
    data = {}

    # Ambil key="value"
    quoted_pairs = re.findall(r'(\w+)="([^"]*)"', text)
    for key, value in quoted_pairs:
        data[key] = value

    # Ambil key=value
    normal_pairs = re.findall(r'\b(\w+)=([^\s"]+)', text)
    for key, value in normal_pairs:
        if key not in data:
            data[key] = value

    return data


def detect_log_type_and_pid(line):
    match = re.search(r'\)\s+([a-zA-Z0-9-]+)(?:\[(\d+)\])?:', line)

    if not match:
        return "unknown", None

    log_type = match.group(1)
    process_id = match.group(2)

    return log_type, int(process_id) if process_id else None


def get_policy(line):
    match = re.search(r'\(([^()]*)\)\s*$', line)

    if match:
        return match.group(1)

    return None


def detect_action(line):
    for action in ["Allow", "Deny", "Block", "Drop"]:
        if f" {action} " in line:
            return action

    return "Unknown"


def detect_protocol(line):
    match = re.search(r'\s(tcp|udp|icmp)\s', line)

    if match:
        return match.group(1)

    return None


def parse_ip_and_port(line):
    result = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
    }

    ip_list = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)

    if len(ip_list) >= 1:
        result["src_ip"] = ip_list[0]

    if len(ip_list) >= 2:
        result["dst_ip"] = ip_list[1]

    if result["src_ip"] and result["dst_ip"]:
        port_pattern = (
            re.escape(result["src_ip"])
            + r'\s+'
            + re.escape(result["dst_ip"])
            + r'\s+(\d+)\s+(\d+)'
        )

        port_match = re.search(port_pattern, line)

        if port_match:
            result["src_port"] = int(port_match.group(1))
            result["dst_port"] = int(port_match.group(2))

    return result


def parse_zones(line):
    result = {
        "from_zone": None,
        "to_zone": None,
    }

    # Hapus key="value" biar token tidak berantakan
    cleaned = re.sub(r'(\w+)="[^"]*"', '', line)
    cleaned = re.sub(r'\b(\w+)=([^\s"]+)', '', cleaned)

    tokens = cleaned.split()

    action_index = None

    for i, token in enumerate(tokens):
        if token in ["Allow", "Deny", "Block", "Drop"]:
            action_index = i
            break

    if action_index is None:
        return result

    after_action = tokens[action_index + 1:]

    protocol_index = None

    for i, token in enumerate(after_action):
        if token in ["tcp", "udp", "icmp"]:
            protocol_index = i
            break

    if protocol_index is None:
        return result

    before_protocol = after_action[:protocol_index]

    if len(before_protocol) >= 2:
        result["from_zone"] = before_protocol[0]
        result["to_zone"] = before_protocol[1]

    return result


def parse_watchguard_log(line, fallback_timestamp=None):
    # Gunakan waktu fetch sebagai timestamp cadangan
    fallback_timestamp = fallback_timestamp or timezone.now()

    data = {
        "timestamp": fallback_timestamp,
        "device_name": None,
        "device_id": None,
        "device_time": fallback_timestamp,

        "log_type": "unknown",
        "process_id": None,
        "msg_id": None,

        "action": "Unknown",
        "from_zone": None,
        "to_zone": None,

        "protocol": None,

        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,

        "geo_src": None,
        "geo_dst": None,

        "policy": None,
        "message": None,

        "app_name": None,
        "cat_name": None,
        "dstname": None,

        "extra_data": {},
        "raw_log": line,
    }

    header_match = re.match(
        r'^(\S+)\s+(\S+)\s+(\S+)\s+\(([^)]+)\)\s+(.+)$',
        line
    )

    if header_match:
        timestamp = parse_datetime(header_match.group(1))
        device_time = parse_datetime(header_match.group(4))

        # Kalau parsing berhasil, gunakan timestamp asli.
        # Kalau gagal, tetap gunakan waktu fetch.
        if timestamp:
            data["timestamp"] = make_aware_if_naive(timestamp)

        if device_time:
            data["device_time"] = make_aware_if_naive(device_time)

        data["device_name"] = header_match.group(2)
        data["device_id"] = header_match.group(3)

    log_type, process_id = detect_log_type_and_pid(line)
    data["log_type"] = log_type
    data["process_id"] = process_id

    kv_data = parse_key_value(line)

    data["msg_id"] = kv_data.get("msg_id")
    data["geo_src"] = kv_data.get("geo_src")
    data["geo_dst"] = kv_data.get("geo_dst")
    data["message"] = kv_data.get("msg")
    data["app_name"] = kv_data.get("app_name")
    data["cat_name"] = kv_data.get("cat_name")
    data["dstname"] = kv_data.get("dstname")

    data["policy"] = get_policy(line)
    data["action"] = detect_action(line)
    data["protocol"] = detect_protocol(line)

    zones = parse_zones(line)
    data["from_zone"] = zones["from_zone"]
    data["to_zone"] = zones["to_zone"]

    ip_port = parse_ip_and_port(line)
    data.update(ip_port)

    main_keys = {
        "msg_id",
        "geo_src",
        "geo_dst",
        "msg",
        "app_name",
        "cat_name",
        "dstname",
    }

    extra_data = {}

    for key, value in kv_data.items():
        if key not in main_keys:
            extra_data[key] = value

    data["extra_data"] = extra_data

    return data