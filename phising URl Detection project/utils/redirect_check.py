"""
utils/redirect_check.py

Expands shortened URLs (bit.ly, tinyurl, t.co, etc.) and traces the full
redirect chain to the final destination. Phishing campaigns frequently
hide the real malicious domain behind one or more redirect hops, so the
detection pipeline should scan the FINAL destination, not just the
shortener link the user pasted in.

Returns a dict shaped so result.html / bulk_results.html can render the
chain directly.
"""

import requests

# Small, well-known list — not exhaustive, but used to flag "this looks
# like a shortener" even if the redirect request itself fails for some
# reason (network issues, shortener down, etc).
KNOWN_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
    "bl.ink", "rb.gy", "tiny.cc", "shorturl.at", "s.id",
}

MAX_HOPS = 8            # safety cap so a redirect loop can't hang the scan
REQUEST_TIMEOUT = 6      # seconds, per hop


def _domain_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        netloc = urlparse(url).netloc.lower()
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


def is_known_shortener(url: str) -> bool:
    return _domain_of(url) in KNOWN_SHORTENER_DOMAINS


def trace_redirect_chain(url: str) -> dict:
    """
    Follows redirects manually (hop by hop, capped at MAX_HOPS) so we can
    report the full chain rather than only the final URL.

    Returns:
        {
            "original_url": str,
            "final_url": str,
            "chain": [url_hop_1, url_hop_2, ...],   # includes original + final
            "hop_count": int,
            "was_shortened": bool,      # True if original looked like a shortener
                                         # OR at least one redirect occurred
            "chain_truncated": bool,    # True if we hit MAX_HOPS without resolving
            "error": str | None,
        }
    """
    chain = [url]
    current = url
    error = None
    truncated = False

    session = requests.Session()
    session.max_redirects = 0  # we handle redirects manually, one hop at a time

    for _ in range(MAX_HOPS):
        try:
            resp = session.head(
                current,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0 (PhishGuard-Scanner)"},
            )
        except requests.exceptions.RequestException:
            # Some shorteners/servers reject HEAD — retry with GET before giving up
            try:
                resp = session.get(
                    current,
                    allow_redirects=False,
                    timeout=REQUEST_TIMEOUT,
                    stream=True,
                    headers={"User-Agent": "Mozilla/5.0 (PhishGuard-Scanner)"},
                )
            except requests.exceptions.RequestException as e:
                error = f"Could not resolve redirect: {e}"
                break

        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                break
            # handle relative redirects
            if location.startswith("/"):
                from urllib.parse import urljoin
                location = urljoin(current, location)
            if location in chain:
                error = "Redirect loop detected."
                break
            chain.append(location)
            current = location
            continue
        else:
            break
    else:
        truncated = True  # loop exhausted MAX_HOPS without a non-redirect response

    return {
        "original_url": url,
        "final_url": chain[-1],
        "chain": chain,
        "hop_count": len(chain) - 1,
        "was_shortened": is_known_shortener(url) or len(chain) > 1,
        "chain_truncated": truncated,
        "error": error,
    }