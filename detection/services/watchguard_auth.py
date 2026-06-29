import requests
import base64

ACCESS_ID = "05b2d5602f5a4074_rw_id"
PASSWORD = "@Polindra4321"
AUTH_URL = "https://api.jpn.cloud.watchguard.com/oauth/token"

# simpan token terakhir di sini
saved_token = None


def get_access_token():
    global saved_token

    credentials = f"{ACCESS_ID}:{PASSWORD}"
    encoded = base64.b64encode(credentials.encode()).decode()

    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {encoded}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    data = {
        "grant_type": "client_credentials",
        "scope": "api-access",
    }

    response = requests.post(
        AUTH_URL,
        headers=headers,
        data=data,
        timeout=60,
    )

    print("GET TOKEN STATUS:", response.status_code)
    print("GET TOKEN RESPONSE:", response.text[:300])

    response.raise_for_status()

    result = response.json()

    token = result.get("access_token")

    if not token:
        raise Exception("Access token tidak ditemukan dari response WatchGuard")

    # token baru tetap disimpan
    saved_token = token

    print("TOKEN BARU DIAMBIL DAN DISIMPAN")

    return saved_token