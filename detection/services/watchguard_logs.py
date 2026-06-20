import requests
from .watchguard_auth import get_access_token

API_KEY = "aPoKpt9iSEwzR/fVC3vGd1INCbH5RUjKT0yUwcYz"
LOGS_URL = "https://api.jpn.cloud.watchguard.com/logs"

def fetch_logs():
    print("Mengambil logs...")
    token = get_access_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "WatchGuard-API-Key": API_KEY
    }
    response = requests.get(
        LOGS_URL,
        headers=headers
    )
    print("Status:", response.status_code)
    response.raise_for_status()
    return response.json()