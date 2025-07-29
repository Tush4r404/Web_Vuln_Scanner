from bs4 import BeautifulSoup

COMMON_CSRF_FIELD_NAMES = [
    "csrf_token", "_csrf", "authenticity_token", "token", "__RequestVerificationToken"
]

def scan_forms_for_csrf(forms):
    findings = []
    for form_url, form in forms:
        hidden_inputs = form.find_all("input", {"type": "hidden"})
        has_csrf = False

        for input_tag in hidden_inputs:
            name = input_tag.get("name", "").lower()
            if name in COMMON_CSRF_FIELD_NAMES:
                has_csrf = True
                break

        if not has_csrf:
            findings.append({
                "type": "Potential CSRF Vulnerability",
                "url": form_url,
                "evidence": "No CSRF token field found in form",
                "severity": "Medium"
            })

    return findings
