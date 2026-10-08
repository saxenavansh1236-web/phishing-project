"""
utils/net_safety.py -- SSRF protection for every outbound fetch.

Your scanner fetches URLs that strangers type in, so an attacker can submit
http://127.0.0.1:5000/admin or http://169.254.169.254/ (cloud metadata) and
make YOUR server request it. Use safe_get() instead of requests.get() for
anything that touches a user-supplied URL.

Known limit: DNS is resolved once for the check and again by requests, so a
DNS-rebinding attacker could still race it. Full protection needs connection
pinning to the checked IP (or running the fetcher in a network-isolated
sandbox). This blocks all the common, practical attacks.
"""
import ipaddress
import socket
from urllib.parse import urlparse, urljoin

import requests

ALLOWED_PORTS = {None, 80, 443, 8080, 8443}
MAX_BYTES = 1_000_000
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PhishGuard/1.0"


UNRESOLVED = "Domain does not resolve"   # not unsafe, just dead (common for taken-down phishing)


class UnsafeURL(Exception):
    pass


def _is_public(ip_str):
    ip = ipaddress.ip_address(ip_str.split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global  # False for private, loopback, link-local, CGNAT, reserved


def check_url_safe(url):
    """Returns (ok, reason)."""
    try:
        p = urlparse(url)
        port = p.port
    except ValueError:
        return False, "Malformed URL"
    if p.scheme not in ("http", "https"):
        return False, "Only http/https URLs are allowed"
    if not p.hostname:
        return False, "URL has no hostname"
    if port not in ALLOWED_PORTS:
        return False, f"Port {port} is not allowed"
    try:
        infos = socket.getaddrinfo(
            p.hostname, port or (443 if p.scheme == "https" else 80),
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror:
        return False, UNRESOLVED
    for info in infos:
        if not _is_public(info[4][0]):
            return False, "Resolves to a non-public address"
    return True, ""


def safe_get(url, timeout=6, max_redirects=5):
    """GET with every redirect hop re-validated. Returns (response, final_url)."""
    current = url
    for _ in range(max_redirects + 1):
        ok, why = check_url_safe(current)
        if not ok:
            raise UnsafeURL(why)
        resp = requests.get(
            current,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        location = resp.headers.get("Location")
        if resp.is_redirect and location:
            resp.close()
            current = urljoin(current, location)
            continue
        return resp, current
    raise UnsafeURL("Too many redirects")


def read_capped(resp, max_bytes=MAX_BYTES):
    """Read at most max_bytes of the body, so a huge response can't exhaust memory."""
    data = b""
    for chunk in resp.iter_content(8192):
        data += chunk
        if len(data) >= max_bytes:
            data = data[:max_bytes]
            break
    resp.close()
    return data