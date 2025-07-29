# scanner/xss_scanner.py
import requests

def scan_url_for_xss(url):
    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert('xss')</script>",
        "'\"><img src=x onerror=alert(1)>"
    ]
    findings = []

    for payload in payloads:
        test_url = url + ("?" if "?" not in url else "&") + f"q={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                findings.append({
                    "type": "XSS",
                    "method": "GET",
                    "url": test_url,
                    "payload": payload,
                    "evidence": payload
                })
        except requests.RequestException:
            continue

    return findings
