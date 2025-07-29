import requests

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "OPTIONS", "PATCH"]

def scan_http_methods(base_url):
    findings = []
    for method in DANGEROUS_METHODS:
        try:
            res = requests.request(method, base_url, timeout=5)
            if res.status_code not in [403, 405]:  # Not blocked
                findings.append({
                    "type": "HTTP Method Tampering",
                    "url": base_url,
                    "method": method,
                    "status_code": res.status_code,
                    "evidence": f"{method} allowed",
                    "severity": "Medium"
                })
        except requests.RequestException:
            continue
    return findings
