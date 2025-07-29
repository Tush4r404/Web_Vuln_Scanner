import requests
from urllib.parse import urljoin

COMMON_ADMIN_PATHS = [
    "admin", "admin/login", "dashboard", "config", "upload",
    "phpinfo.php", "phpmyadmin", "server-status", ".git/", ".env",
    "wp-admin", "administrator"
]

def scan_common_admin_paths(base_url):
    findings = []
    for path in COMMON_ADMIN_PATHS:
        test_url = urljoin(base_url + "/", path)
        try:
            res = requests.get(test_url, timeout=5)
            if res.status_code == 200 and "login" in res.text.lower():
                findings.append({
                    "type": "Admin Panel Exposure",
                    "url": test_url,
                    "status_code": res.status_code,
                    "evidence": "Accessible login panel or dashboard",
                    "severity": "High"
                })
            elif res.status_code == 200:
                findings.append({
                    "type": "Sensitive Path Exposed",
                    "url": test_url,
                    "status_code": res.status_code,
                    "evidence": "Accessible page",
                    "severity": "Medium"
                })
        except requests.RequestException:
            continue
    return findings
