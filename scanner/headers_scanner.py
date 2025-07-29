import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps prevent XSS",
    "Strict-Transport-Security": "Enforces HTTPS",
    "X-Frame-Options": "Protects against clickjacking",
    "X-Content-Type-Options": "Blocks MIME-type sniffing",
    "Referrer-Policy": "Controls referer header",
    "Permissions-Policy": "Limits browser features"
}

def scan_security_headers(url):
    findings = []
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers

        for header, desc in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append({
                    "type": "Missing Security Header",
                    "header": header,
                    "description": desc,
                    "url": url,
                    "severity": "Medium"
                })

    except requests.RequestException:
        pass

    return findings
