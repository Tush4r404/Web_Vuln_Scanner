import requests

def scan_insecure_cookies(url):
    findings = []

    try:
        response = requests.get(url, timeout=5)
        cookies = response.headers.get("Set-Cookie")

        if cookies:
            cookie_list = cookies.split(",")
            for raw_cookie in cookie_list:
                cookie = raw_cookie.strip()
                issues = []

                if "HttpOnly" not in cookie:
                    issues.append("Missing HttpOnly")
                if "Secure" not in cookie and url.startswith("https"):
                    issues.append("Missing Secure")
                if "SameSite" not in cookie:
                    issues.append("Missing SameSite")

                if issues:
                    findings.append({
                        "type": "Insecure Cookie",
                        "cookie": cookie,
                        "issues": issues,
                        "url": url,
                        "severity": "Medium"
                    })
    except requests.RequestException:
        pass

    return findings
