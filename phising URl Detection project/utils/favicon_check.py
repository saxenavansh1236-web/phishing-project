"""
utils/favicon_check.py

Favicon-based visual similarity detection.

Many phishing sites clone a target brand's exact visual identity —
including the favicon — while hosting on a completely unrelated domain
(e.g. "paypal-secure-login.tk" using PayPal's real favicon). A byte-level
image comparison would fail here because favicons get re-compressed,
resized, or re-encoded, so this module uses PERCEPTUAL hashing (phash),
which is robust to those changes and only cares about visual structure.

Pipeline:
    1. Locate the site's favicon (checks common paths + parses <link> tags)
    2. Download it and compute a perceptual hash (64-bit phash)
    3. Compare that hash (Hamming distance) against a small local
       database of known-brand favicon hashes (utils/known_favicons.json)
    4. If the hash is a close match to a brand BUT the domain being
       scanned isn't that brand's real domain -> flag as a likely
       visual clone / brand impersonation attempt

The known-brand database is built once (offline, with real internet
access) using scripts/build_favicon_db.py — see that file's docstring.
This module only ever reads the resulting JSON at runtime.
"""

import io
import json
import os
import re
from urllib.parse import urljoin, urlparse

import requests

try:
    from PIL import Image
    import imagehash
    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False

REQUEST_TIMEOUT = 6
HAMMING_MATCH_THRESHOLD = 10   # phash bits differing; <=10 on a 64-bit hash is a strong visual match
KNOWN_DB_PATH = os.path.join(os.path.dirname(__file__), "known_favicons.json")

HEADERS = {"User-Agent": "Mozilla/5.0 (PhishGuard-FaviconCheck)"}


def _normalize_url(url: str) -> str:
    """
    requests (and urljoin) require a URL with a scheme — "google.com"
    fails, "https://google.com" works. Other checks in this project
    (e.g. SSL inspection) may work directly off a bare hostname via raw
    sockets, but this module goes through requests/urljoin, so every
    entry point here normalizes first. Without this, EVERY domain
    (legitimate or malicious) silently fails favicon retrieval whenever
    a bare domain is scanned — which looks identical to "no favicon
    found" and is easy to misdiagnose as a site-specific problem.
    """
    url = url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = "https://" + url
    return url


def _root_domain(url: str) -> str:
    netloc = urlparse(url).netloc.lower()
    return netloc[4:] if netloc.startswith("www.") else netloc


def _candidate_favicon_urls(url: str) -> list:
    """
    Builds a short list of places a favicon is likely to be, in priority
    order: parsed <link> tags from the page HTML first (most accurate),
    then the standard /favicon.ico fallback every browser also tries.
    """
    candidates = []
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        html = resp.text[:200_000]  # cap — we only need the <head>, not the whole page
        for match in re.finditer(
            r'<link[^>]+rel=["\'](?:shortcut icon|icon|apple-touch-icon)["\'][^>]*>',
            html,
            re.IGNORECASE,
        ):
            tag = match.group(0)
            href_match = re.search(r'href=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if href_match:
                candidates.append(urljoin(url, href_match.group(1)))
    except requests.exceptions.RequestException:
        pass

    # HTTPS fallback first, then HTTP, in case the site's cert is broken
    # but the favicon is still reachable over the fallback scheme used
    # elsewhere in the redirect trace.
    candidates.append(urljoin(url, "/favicon.ico"))
    return candidates


def _download_image(favicon_url: str):
    try:
        resp = requests.get(favicon_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200 or not resp.content:
            return None
        return Image.open(io.BytesIO(resp.content)).convert("RGBA")
    except Exception:
        return None


def _load_known_db() -> dict:
    if not os.path.exists(KNOWN_DB_PATH):
        return {}
    try:
        with open(KNOWN_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def check_favicon_similarity(url: str) -> dict:
    """
    Returns:
        {
            "supported": bool,           # False if Pillow/imagehash aren't installed
            "has_favicon": bool,
            "favicon_url": str | None,
            "phash": str | None,
            "matched_brand": str | None,      # e.g. "PayPal"
            "matched_domains": list,          # that brand's legitimate domain(s)
            "hamming_distance": int | None,
            "is_visual_clone": bool,          # True = looks like a brand, but domain doesn't match
            "risk": "high" | "medium" | "low" | "unknown",
            "note": str,
        }
    """
    base = {
        "supported": _DEPS_OK,
        "has_favicon": False,
        "favicon_url": None,
        "phash": None,
        "matched_brand": None,
        "matched_domains": [],
        "hamming_distance": None,
        "is_visual_clone": False,
        "risk": "unknown",
        "note": "",
    }

    if not _DEPS_OK:
        base["note"] = "Pillow / ImageHash not installed — favicon check skipped."
        return base

    url = _normalize_url(url)   # <-- THE FIX: guarantee a scheme before any requests/urljoin call

    known_db = _load_known_db()
    if not known_db:
        base["note"] = (
            "No known-brand favicon database found. Run "
            "scripts/build_favicon_db.py once to populate utils/known_favicons.json."
        )

    scanned_domain = _root_domain(url)

    image = None
    used_favicon_url = None
    for candidate in _candidate_favicon_urls(url):
        image = _download_image(candidate)
        if image is not None:
            used_favicon_url = candidate
            break

    if image is None:
        base["note"] = base["note"] or "No favicon could be retrieved for this domain."
        return base

    base["has_favicon"] = True
    base["favicon_url"] = used_favicon_url

    try:
        scanned_hash = imagehash.phash(image)
    except Exception:
        base["note"] = "Favicon found but could not be hashed (unsupported image format)."
        return base

    base["phash"] = str(scanned_hash)

    if not known_db:
        return base

    best_brand = None
    best_distance = None
    best_domains = []

    for brand, entry in known_db.items():
        try:
            brand_hash = imagehash.hex_to_hash(entry["phash"])
        except (KeyError, ValueError):
            continue
        distance = scanned_hash - brand_hash  # Hamming distance
        if best_distance is None or distance < best_distance:
            best_distance = distance
            best_brand = brand
            best_domains = entry.get("domains", [])

    if best_distance is None:
        return base

    base["matched_brand"] = best_brand
    base["matched_domains"] = best_domains
    base["hamming_distance"] = best_distance

    is_close_match = best_distance <= HAMMING_MATCH_THRESHOLD
    domain_is_legitimate = scanned_domain in [d.lower() for d in best_domains]

    if is_close_match and not domain_is_legitimate:
        base["is_visual_clone"] = True
        base["risk"] = "high"
        base["note"] = (
            f"Favicon closely matches {best_brand} (Hamming distance {best_distance}) "
            f"but the domain '{scanned_domain}' does not match {best_brand}'s known domain(s)."
        )
    elif is_close_match and domain_is_legitimate:
        base["risk"] = "low"
        base["note"] = f"Favicon matches {best_brand} and the domain is one of its legitimate domains."
    else:
        base["risk"] = "low"
        base["note"] = "No close visual match to any known brand in the local database."

    return base