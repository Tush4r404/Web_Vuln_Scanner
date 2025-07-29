import requests

COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("user", "user"),
    ("root", "root"),
    ("test", "test"),
    ("admin", "1234"),
]

def scan_weak_login(forms, base_url):
    findings = []

    for item in forms:
        form, form_url = item
        inputs = form.get("inputs", {})

        username_fields = [name for name in inputs if "user" in name.lower() or "email" in name.lower()]
        password_fields = [name for name in inputs if "pass" in name.lower()]

        if not username_fields or not password_fields:
            continue  # not a login form

        uname_field = username_fields[0]
        pass_field = password_fields[0]

        for username, password in COMMON_CREDENTIALS:
            data = {uname_field: username, pass_field: password}

            try:
                response = requests.post(form_url, data=data, timeout=5)

                if "invalid" not in response.text.lower() and "error" not in response.text.lower():
                    findings.append({
                        "type": "Weak Login Credentials",
                        "url": form_url,
                        "credentials": data,
                        "severity": "High",
                        "evidence": f"Form responded without obvious error to {username}/{password}"
                    })
                    break  # no need to keep guessing
            except Exception:
                continue

    return findings
