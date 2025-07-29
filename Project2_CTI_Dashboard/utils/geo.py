import requests

def lookup_geo_info(ioc):
    try:
        url = f"http://ip-api.com/json/{ioc}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()  # Flat JSON
        return {"error": "Geo Info lookup failed", "status_code": response.status_code}
    except Exception as e:
        return {"error": str(e)}
