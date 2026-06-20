import requests
import base64

ACCESS_ID = "05b2d5602f5a4074_rw_id"
PASSWORD = "@Polindra4321"
AUTH_URL = "https://api.jpn.cloud.watchguard.com/oauth/token"

# simpan token di sini
saved_token = None


def get_access_token():
    global saved_token
    # kalau token sudah ada
    if saved_token:
        print("Pakai token yang disimpan")
        return saved_token
    credentials = f"{ACCESS_ID}:{PASSWORD}"
    encoded = base64.b64encode(
        credentials.encode()
    ).decode()
    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {encoded}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "client_credentials",
        "scope": "api-access"
    }
    response = requests.post(
        AUTH_URL,
        headers=headers,
        data=data
    )
    print("STATUS:", response.status_code)
    print("RESPONSE:", response.text)
    response.raise_for_status()
    result = response.json()
    
    # simpan token
    saved_token = result["access_token"]
    print("TOKEN DISIMPAN")
    return saved_token