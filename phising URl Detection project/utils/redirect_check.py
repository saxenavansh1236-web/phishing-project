"""
utils/redirect_check.py

Expands shortened URLs (bit.ly, tinyurl, t.co, etc.) and traces the full
redirect chain to the final destination. Phishing campaigns frequently
hide the real malicious domain behind one or more redirect hops, so the
detection pipeline should scan the FINAL destination, not just the
shortener link the user pasted in.

SSRF-hardened: every hop is validated with check_url_safe() BEFORE it is
requested, so a link (or a redirect) pointing at 127.0.0.1, 169.254.169.254,
10.x.x.x etc. is never contacted. If that happens the result has
"blocked": True and the caller must skip all further network checks.
"""

from urllib.parse import urlparse, urljoin

import requests

from utils.net_safety import check_url_safe, UNRESOLVED

KNOWN_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
    "bl.ink", "rb.gy", "tiny.cc", "shorturl.at", "s.id",
}

MAX_HOPS = 8            # safety cap so a redirect loop can't hang the scan
REQUEST_TIMEOUT = 6     # seconds, per hop
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PhishGuard/1.0"}


def _domain_of(url: str) -> str:
    try:
        netloc = urlparse(url).netloc.lower()
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


def is_known_shortener(url: str) -> bool:
    return _domain_of(url) in KNOWN_SHORTENER_DOMAINS


def trace_redirect_chain(url: str) -> dict:
    """
    Returns:
        {
            "original_url": str,
            "final_url": str,
            "chain": [...],            # includes original + final
            "hop_count": int,
            "was_shortened": bool,
            "chain_truncated": bool,
            "blocked": bool,           # True if a hop pointed at a non-public address
            "error": str | None,
        }
    """
    chain = [url]
    current = url
    error = None
    truncated = False
    blocked = False

    session = requests.Session()

    for _ in range(MAX_HOPS):
        ok, why = check_url_safe(current)
        if not ok:
            if why == UNRESOLVED:
                error = "Domain does not resolve (site may be offline or taken down)."
            else:
                blocked = True
                error = f"Blocked: {why}"
            break

        resp = None
        try:
            resp = session.head(current, allow_redirects=False,
                                timeout=REQUEST_TIMEOUT, headers=HEADERS)
        except requests.exceptions.RequestException:
            # Some servers reject HEAD — retry with GET before giving up
            try:
                resp = session.get(current, allow_redirects=False,
                                   timeout=REQUEST_TIMEOUT, stream=True, headers=HEADERS)
            except requests.exceptions.RequestException as e:
                error = f"Could not resolve redirect: {e}"
                break

        try:
            is_redirect = resp.status_code in (301, 302, 303, 307, 308)
            location = resp.headers.get("Location")
        finally:
            resp.close()

        if not is_redirect or not location:
            break

        location = urljoin(current, location)   # handles relative, //host and absolute
        if location in chain:
            error = "Redirect loop detected."
            break
        chain.append(location)
        current = location
    else:
        truncated = True  # loop exhausted MAX_HOPS without a non-redirect response
        # the last appended hop was never validated inside the loop
        ok, why = check_url_safe(chain[-1])
        if not ok and why != UNRESOLVED:
            blocked = True
            error = f"Blocked: {why}"

    # If the LAST hop was blocked, final_url is that unsafe URL; callers must
    # check "blocked" before running any other network check against it.
    return {
        "original_url": url,
        "final_url": chain[-1],
        "chain": chain,
        "hop_count": len(chain) - 1,
        "was_shortened": is_known_shortener(url) or len(chain) > 1,
        "chain_truncated": truncated,
        "blocked": blocked,
        "error": error,
    }