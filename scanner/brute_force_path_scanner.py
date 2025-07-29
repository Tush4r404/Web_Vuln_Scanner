import requests
from urllib.parse import urljoin

COMMON_LOGIN_PATHS = ["login", "admin", "admin/login", "user/login", "account/login"]

CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("user", "user"),
    ("test", "test")
]

def scan_weak_logins(base_url):
    findings = []

    for path in COMMON_LOGIN_PATHS:
        login_url = urljoin(base_url + "/", path)
        for username, password in CREDENTIALS:
            try:
                res = requests.post(
                    login_url,
                    data={"username": username, "password": password},
                    timeout=5,
                    allow_redirects=False
                )

                # Heuristic: login success if status code 302 or login keyword missing in response
                if res.status_code in (200, 302) and "login" not in res.text.lower():
                    findings.append({
                        "type": "Weak Login Credentials",
                        "url": login_url,
                        "username": username,
                        "password": password,
                        "evidence": f"Response code: {res.status_code}",
                        "severity": "High"
                    })
                    break  # Stop testing more creds on this path if one works
            except requests.RequestException:
                continue

    return findings
