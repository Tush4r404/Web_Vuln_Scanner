import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Simplified database of outdated versions (can be expanded)
KNOWN_VULNERABLE_JS = {
    "jquery": ["1.7", "1.8", "1.9", "1.10", "1.11", "2.0", "2.1", "2.2", "3.0", "3.1"],
    "angular": ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"],
    "bootstrap": ["3.0", "3.1", "3.2", "3.3"]
}

def extract_lib_version(src):
    for lib, versions in KNOWN_VULNERABLE_JS.items():
        if lib in src.lower():
            match = re.search(rf"{lib}[-.]?(\d+\.\d+)", src, re.I)
            if match:
                version = match.group(1)
                if version in versions:
                    return lib, version
    return None, None

def scan_outdated_js(pages):
    findings = []
    for page in pages:
        try:
            res = requests.get(page, timeout=5)
            soup = BeautifulSoup(res.text, "html.parser")
            scripts = soup.find_all("script", src=True)

            for script in scripts:
                src = script['src']
                full_url = urljoin(page, src)
                lib, version = extract_lib_version(src)
                if lib:
                    findings.append({
                        "type": "Outdated JS Library",
                        "library": lib,
                        "version": version,
                        "script_url": full_url,
                        "page": page,
                        "severity": "Medium"
                    })
        except requests.RequestException:
            continue

    return findings
