import requests
from urllib.parse import urlparse, urljoin

REDIRECT_PARAMS = ['next', 'url', 'redirect', 'return', 'continue']

def scan_open_redirects(pages):
    findings = []
    test_url = "https://evil.com"  # Malicious redirection test

    for page in pages:
        parsed = urlparse(page)
        for param in REDIRECT_PARAMS:
            test_link = f"{page}?{param}={test_url}"
            try:
                res = requests.get(test_link, allow_redirects=False, timeout=5)
                if res.status_code in [301, 302] and 'Location' in res.headers:
                    location = res.headers['Location']
                    if test_url in location:
                        findings.append({
                            "type": "Open Redirect",
                            "url": test_link,
                            "param": param,
                            "redirects_to": location,
                            "severity": "Medium"
                        })
            except requests.RequestException:
                continue

    return findings
