import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def scan_crypto_misconfigurations(base_url):
    findings = []
    parsed = urlparse(base_url)
    
    # Skip non-HTTPS URLs
    if parsed.scheme != "https":
        findings.append({
            "type": "TLS Scan Skipped",
            "url": base_url,
            "evidence": "Non-HTTPS URL, skipping TLS checks",
            "severity": "Info"
        })
        return findings

    hostname = parsed.hostname
    port = 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    common_name = subject.get("commonName", "")
                    issued_by = issuer.get("commonName", "")
                    findings.append({
                        "type": "TLS Certificate Info",
                        "url": base_url,
                        "evidence": f"Issued to: {common_name}, by: {issued_by}",
                        "severity": "Info"
                    })

                    exp = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    if exp < datetime.utcnow():
                        findings.append({
                            "type": "Expired TLS Certificate",
                            "url": base_url,
                            "evidence": f"Expired at {cert['notAfter']}",
                            "severity": "High"
                        })

    except ssl.SSLError as e:
        findings.append({
            "type": "SSL Error",
            "url": base_url,
            "evidence": str(e),
            "severity": "High"
        })
    except socket.timeout:
        findings.append({
            "type": "TLS Timeout",
            "url": base_url,
            "evidence": "Connection to port 443 timed out",
            "severity": "Medium"
        })
    except Exception as e:
        findings.append({
            "type": "Connection Error",
            "url": base_url,
            "evidence": str(e),
            "severity": "Medium"
        })

    return findings
