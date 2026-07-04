"""
ssl_check.py
Inspects the SSL/TLS certificate of a URL's domain and flags suspicious
characteristics: no cert at all, expired, self-signed, or issued by a
free/throwaway CA. Uses only Python's built-in ssl + socket modules,
no extra pip installs needed.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

# CAs commonly abused for quick, free, low-verification certs.
# Not inherently malicious (Let's Encrypt secures huge parts of the
# legitimate web) — but combined with other red flags, worth flagging.
FREE_CA_KEYWORDS = ["let's encrypt", "zerossl", "cloudflare"]


def _get_domain(url):
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.hostname or url.replace("http://", "").replace("https://", "").split("/")[0]


def check_ssl_certificate(url, timeout=5):
    """
    Returns a dict describing the SSL/TLS certificate state for the URL's domain.
    Always returns a dict — never raises — so it's safe to call unconditionally
    in your scan route even for plain http:// URLs or unreachable hosts.
    """
    domain = _get_domain(url)

    result = {
        "has_cert": False,
        "is_expired": None,
        "is_self_signed": None,
        "issuer": None,
        "issuer_is_free_ca": False,
        "days_until_expiry": None,
        "risk": "unknown",
        "notes": [],
    }

    try:
        context = ssl.create_default_context()
        # don't hard-fail on hostname/verification issues — we WANT to inspect
        # self-signed / invalid certs too, not just reject the connection
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)

        result["has_cert"] = True

        # Parse the raw DER certificate properly — works regardless of
        # verify_mode, unlike the legacy getpeercert() dict format.
        cert = x509.load_der_x509_certificate(cert_bin, default_backend())

        def _get_cn(name):
            try:
                return name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            except (IndexError, Exception):
                return None

        def _get_org(name):
            try:
                return name.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
            except (IndexError, Exception):
                return None

        issuer_cn = _get_cn(cert.issuer)
        issuer_org = _get_org(cert.issuer) or issuer_cn
        subject_cn = _get_cn(cert.subject)

        result["issuer"] = issuer_org or "Unknown issuer"
        result["is_self_signed"] = bool(subject_cn and issuer_cn and subject_cn == issuer_cn)

        # Expiry (cryptography >=42 uses not_valid_after_utc; older uses not_valid_after)
        expiry = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days
        result["days_until_expiry"] = days_left
        result["is_expired"] = days_left < 0

        # Free/throwaway CA check
        if result["issuer"]:
            issuer_lower = result["issuer"].lower()
            result["issuer_is_free_ca"] = any(kw in issuer_lower for kw in FREE_CA_KEYWORDS)

        # ── Risk scoring + human-readable notes ──
        if result["is_expired"]:
            result["risk"] = "high"
            result["notes"].append("SSL certificate has expired")
        elif result["is_self_signed"]:
            result["risk"] = "high"
            result["notes"].append("Certificate is self-signed (not issued by a trusted CA)")
        elif result["days_until_expiry"] is not None and result["days_until_expiry"] < 14:
            result["risk"] = "medium"
            result["notes"].append("Certificate expires very soon")
        elif result["issuer_is_free_ca"]:
            result["risk"] = "low"
            result["notes"].append(f"Issued by a free CA ({result['issuer']}) — common for legitimate sites, but also popular with short-lived phishing domains")
        else:
            result["risk"] = "low"
            result["notes"].append("Certificate appears valid and properly issued")

    except (socket.timeout, ConnectionRefusedError, OSError):
        result["has_cert"] = False
        result["risk"] = "high"
        result["notes"].append("No HTTPS/SSL certificate found — connection to port 443 failed")
    except ssl.SSLError as e:
        result["has_cert"] = False
        result["risk"] = "high"
        result["notes"].append(f"SSL handshake failed: {e}")
    except Exception as e:
        result["risk"] = "unknown"
        result["notes"].append(f"Could not inspect certificate: {e}")

    return result