import requests
import os

API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def lookup_virustotal(ioc: str) -> dict:
    headers = {"x-apikey": API_KEY}
    url = f"{BASE_URL}{ioc}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {})
    except Exception as e:
        return {"error": str(e)}
    return {"error": "VirusTotal lookup failed"}
