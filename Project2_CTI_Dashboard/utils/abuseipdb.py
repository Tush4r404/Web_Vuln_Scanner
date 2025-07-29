import requests
import os

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2/check"

def lookup_abuseipdb(ioc: str) -> dict:
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ioc,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(BASE_URL, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {})
    except Exception as e:
        return {"error": str(e)}
    return {"error": "AbuseIPDB lookup failed"}
