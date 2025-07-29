# scanner/scanner.py
import requests

def scan_forms_for_sqli(forms, base_url):
    payloads = ["' OR '1'='1", "' OR 1=1 --", "' OR '1'='1' --"]
    findings = []

    for item in forms:
        if not isinstance(item, tuple) or len(item) != 2:
            continue

        form, form_url = item
        if not isinstance(form, dict):
            continue

        inputs = form.get("inputs", {})
        for payload in payloads:
            data = {name: payload for name in inputs}

            try:
                response = requests.post(form_url, data=data, timeout=5)
                if "sql" in response.text.lower() or "syntax" in response.text.lower():
                    findings.append({
                        "type": "SQLi",
                        "method": "POST",
                        "form_url": form_url,
                        "payload": data,
                        "evidence": "SQL error in response"
                    })
            except Exception:
                continue

    return findings
