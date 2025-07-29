import requests

COMMON_DIRS = [
    "uploads", "backup", "backups", "admin", "logs", "files", "tmp", "temp", ".git", ".svn"
]

def scan_directory_listing(base_url):
    if not base_url.endswith("/"):
        base_url += "/"
        
    findings = []

    for path in COMMON_DIRS:
        test_url = base_url + path + "/"
        try:
            res = requests.get(test_url, timeout=5)
            if res.status_code == 200 and "Index of /" in res.text and "<title>Index of" in res.text:
                findings.append({
                    "type": "Directory Listing",
                    "url": test_url,
                    "evidence": "Index of found in response",
                    "severity": "Medium"
                })
        except requests.RequestException:
            continue

    return findings
