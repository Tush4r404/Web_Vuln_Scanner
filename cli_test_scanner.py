# cli_test_scanner.py

import sys
import time
import json
import argparse
from collections import Counter
from colorama import init, Fore, Style
from scanner.crawler import crawl
from scanner.xss_scanner import scan_url_for_xss
from scanner.scanner import scan_forms_for_sqli
from scanner.csrf_scanner import scan_forms_for_csrf
from scanner.headers_scanner import scan_security_headers
from scanner.admin_scanner import scan_common_admin_paths
from scanner.js_scanner import scan_outdated_js
from scanner.open_redirect_scanner import scan_open_redirects
from scanner.directory_listing_scanner import scan_directory_listing
from scanner.cookie_scanner import scan_insecure_cookies
from scanner.crypto_scanner import scan_crypto_misconfigurations
from scanner.http_methods_scanner import scan_http_methods
from scanner.brute_force_form_scanner import scan_for_weak_login
from database.db import save_scan_results
from utils.html_report import generate_html_report
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)

def colorize(severity, text):
    return {
        "High": Fore.RED + text + Style.RESET_ALL,
        "Medium": Fore.YELLOW + text + Style.RESET_ALL,
        "Info": Fore.CYAN + text + Style.RESET_ALL
    }.get(severity, text)

def log(msg, verbose=True, severity=None):
    if verbose:
        if severity:
            print(colorize(severity, msg))
        else:
            print(msg)

def main():
    parser = argparse.ArgumentParser(description="[*] CLI Vulnerability Scanner")
    parser.add_argument("target", help="Target URL (e.g., http://example.com)")
    parser.add_argument("--output", help="Output file to save JSON results", default="scan_log.json")
    parser.add_argument("--html-report", help="Output HTML report file", default=None)
    parser.add_argument("--delay", help="Delay between requests (in seconds)", type=float, default=0.5)
    parser.add_argument("--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("--threads", help="Number of threads for concurrent scanning", type=int, default=10)
    args = parser.parse_args()

    base_url = args.target
    all_findings = []

    print(f"\n[+] Target: {base_url}")

    print("\n[*] Crawling target...")
    pages, forms = crawl(base_url)
    print(f" - {len(pages)} pages found")
    print(f" - {len(forms)} forms found")

    print(f"\n[*] Scanning {len(pages)} pages for XSS...")
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_url_for_xss, page) for page in pages]
        for future in as_completed(futures):
            time.sleep(args.delay)
            results = future.result()
            all_findings.extend(results)
            for r in results:
                log(f"[!] XSS Found: {r}", args.verbose, r.get("severity", "High"))
    log(f"[+] XSS scan completed. {len([f for f in all_findings if f['type'] == 'XSS'])} issues.", args.verbose)

    print(f"\n[*] Scanning {len(forms)} forms for SQLi...")
    sqli_results = scan_forms_for_sqli(forms, base_url)
    all_findings.extend(sqli_results)
    for r in sqli_results:
        log(f"[!] SQLi Found: {r}", args.verbose, r.get("severity", "High"))
    log(f"[+] SQLi scan completed. {len(sqli_results)} total issues so far.", args.verbose)

    print("\n[*] Scanning for directory listing...")
    for page in pages:
        results = scan_directory_listing(page)
        all_findings.extend(results)
        for r in results:
            log(f"[*] Directory Listing Found: {r}", args.verbose, r.get("severity", "Medium"))

    print("\n[*] Scanning forms for CSRF token absence...")
    csrf_results = scan_forms_for_csrf(forms)
    all_findings.extend(csrf_results)
    for r in csrf_results:
        log(f"[!] CSRF: {r}", args.verbose, r.get("severity", "Medium"))

    print("\n[*] Scanning for missing security headers...")
    headers_results = scan_security_headers(base_url)
    all_findings.extend(headers_results)
    for r in headers_results:
        log(f"[!] Headers: {r}", args.verbose, r.get("severity", "Medium"))

    print("\n[*] Scanning for exposed admin paths...")
    admin_results = scan_common_admin_paths(base_url)
    all_findings.extend(admin_results)
    for r in admin_results:
        log(f"[!] Admin Exposure: {r}", args.verbose, r.get("severity", "Medium"))

    print("\n[*] Scanning for outdated JavaScript libraries...")
    js_results = scan_outdated_js(pages)
    all_findings.extend(js_results)
    for r in js_results:
        log(f"[*] JS Library Issue: {r}", args.verbose, r.get("severity", "Medium"))

    print("\n[+] Scanning for open redirects...")
    redirect_results = scan_open_redirects(pages)
    all_findings.extend(redirect_results)
    for r in redirect_results:
        log(f"[+] Open Redirect: {r}", args.verbose, r.get("severity", "Medium"))

    print("\n[*] Scanning for insecure cookie flags...")
    for page in pages:
        cookie_results = scan_insecure_cookies(page)
        all_findings.extend(cookie_results)
        for r in cookie_results:
            log(f"[*] Insecure Cookie: {r}", args.verbose, r.get("severity", "Medium"))

    print("\n[*] Scanning for cryptographic misconfigurations...")
    crypto_results = scan_crypto_misconfigurations(base_url)
    all_findings.extend(crypto_results)
    for r in crypto_results:
        log(f"[*] TLS: {r}", args.verbose, r.get("severity", "Info"))

    print("\n[*] Scanning for HTTP method tampering...")
    method_results = scan_http_methods(base_url)
    all_findings.extend(method_results)
    for r in method_results:
        log(f"[*] HTTP Method Issue: {r}", args.verbose, r.get("severity", "Medium"))

    print("\n[*] Scanning for weak login forms...")
    weak_login_results = scan_for_weak_login(forms)
    all_findings.extend(weak_login_results)
    for r in weak_login_results:
        log(f"[*] Weak Login Found: {r}", args.verbose, r.get("severity", "High"))

    # Save results
    save_scan_results(base_url, all_findings)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2)

    if args.html_report:
        generate_html_report(all_findings, output_path=args.html_report, target=base_url)
        print(f"\n[*] HTML report saved to {args.html_report}")

    # Final summary
    severity_counts = Counter([finding.get("severity", "Uncategorized") for finding in all_findings])
    print("\n[=] Final Summary by Severity:")
    for level in ["High", "Medium", "Info", "Uncategorized"]:
        if severity_counts[level]:
            print(colorize(level, f" - {level}: {severity_counts[level]} issues"))

    print(f"\n[+] Scan complete. {len(all_findings)} issues saved to MongoDB and {args.output}")

if __name__ == "__main__":
    main()
