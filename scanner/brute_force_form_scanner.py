import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

COMMON_LOGIN_KEYWORDS = ['login', 'signin']
CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("user", "123456"),
    ("test", "test123"),
]

def scan_for_weak_login(forms):
    findings = []

    for form_url, form in forms:
        inputs = form.find_all("input")
        form_data = {}
        has_user = has_pass = False

        action = form.get("action")
        method = form.get("method", "get").lower()
        full_url = urljoin(form_url, action) if action else form_url

        for inp in inputs:
            name = inp.get("name", "").lower()
            if "user" in name or "email" in name:
                form_data["username_field"] = name
                has_user = True
            elif "pass" in name:
                form_data["password_field"] = name
                has_pass = True

        if has_user and has_pass:
            for username, password in CREDENTIALS:
                payload = {
                    form_data["username_field"]: username,
                    form_data["password_field"]: password
                }

                try:
                    if method == "post":
                        res = requests.post(full_url, data=payload, timeout=5)
                    else:
                        res = requests.get(full_url, params=payload, timeout=5)

                    if not any(x in res.text.lower() for x in ["invalid", "incorrect", "wrong password", "failed"]):
                        findings.append({
                            "type": "Weak Login Credentials Accepted",
                            "url": full_url,
                            "username": username,
                            "password": password,
                            "severity": "High"
                        })
                        break  # stop after one success
                except requests.RequestException:
                    continue

    return findings
