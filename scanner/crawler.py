import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"}

def crawl(base_url, max_depth=2):
    visited = set()
    to_visit = [(base_url, 0)]
    discovered_forms = []

    while to_visit:
        current_url, depth = to_visit.pop()
        if current_url in visited or depth > max_depth:
            continue

        try:
            res = requests.get(current_url, timeout=5)
            visited.add(current_url)

            soup = BeautifulSoup(res.text, "html.parser")

            # Collect forms
            forms = soup.find_all("form")
            discovered_forms += [(current_url, form) for form in forms]

            # Find new links
            for a in soup.find_all("a", href=True):
                href = urljoin(current_url, a['href'])
                if base_url in href and is_valid_url(href):
                    to_visit.append((href, depth + 1))

        except requests.RequestException:
            continue

    return list(visited), discovered_forms
