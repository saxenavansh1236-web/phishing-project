"""
utils/favicon_check.py

Favicon-based visual similarity detection (perceptual hashing).

Many phishing sites clone a brand's exact favicon while hosting on an unrelated
domain. Byte-level comparison fails (re-compression, resizing), so this uses
perceptual hashing (phash) and compares Hamming distance against a local
database of known-brand hashes (utils/known_favicons.json, built offline by
scripts/build_favicon_db.py).

SSRF-hardened: every network fetch goes through utils.net_safety.safe_get(),
so a page can't point its <link rel="icon"> at an internal address, and
downloads are size-capped.
"""

import io
import json
import os
import re
from urllib.parse import urljoin, urlparse

import requests

from utils.net_safety import safe_get, read_capped, UnsafeURL

try:
    from PIL import Image
    import imagehash
    Image.MAX_IMAGE_PIXELS = 5_000_000   # refuse decompression bombs
    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False

HAMMING_MATCH_THRESHOLD = 10   # <=10 differing bits on a 64-bit phash is a strong match
KNOWN_DB_PATH = os.path.join(os.path.dirname(__file__), "known_favicons.json")
MAX_HTML_BYTES = 200_000
MAX_ICON_BYTES = 300_000


def _normalize_url(url: str) -> str:
    """requests/urljoin need a scheme; bare domains like 'google.com' get https://."""
    url = url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = "https://" + url
    return url


def _root_domain(url: str) -> str:
    netloc = urlparse(url).netloc.lower()
    return netloc[4:] if netloc.startswith("www.") else netloc


def _candidate_favicon_urls(url: str) -> list:
    """<link> icons from the page first (most accurate), then /favicon.ico."""
    candidates = []
    try:
        resp, final_url = safe_get(url)
        html = read_capped(resp, MAX_HTML_BYTES).decode(resp.encoding or "utf-8", errors="replace")
        for match in re.finditer(
            r'<link[^>]+rel=["\'](?:shortcut icon|icon|apple-touch-icon)["\'][^>]*>',
            html, re.IGNORECASE,
        ):
            href = re.search(r'href=["\']([^"\']+)["\']', match.group(0), re.IGNORECASE)
            if href:
                candidates.append(urljoin(final_url, href.group(1)))
    except (UnsafeURL, requests.exceptions.RequestException):
        pass
    candidates.append(urljoin(url, "/favicon.ico"))
    return candidates


def _download_image(favicon_url: str):
    try:
        resp, _ = safe_get(favicon_url)
        if resp.status_code != 200:
            resp.close()
            return None
        data = read_capped(resp, MAX_ICON_BYTES)
        if not data:
            return None
        return Image.open(io.BytesIO(data)).convert("RGBA")
    except Exception:   # unsafe URL, network error, bad image: all mean "no favicon"
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
    Returns a dict with: supported, has_favicon, favicon_url, phash,
    matched_brand, matched_domains, hamming_distance, is_visual_clone,
    risk ("high"|"low"|"unknown"), note.
    """
    base = {
        "supported": _DEPS_OK, "has_favicon": False, "favicon_url": None,
        "phash": None, "matched_brand": None, "matched_domains": [],
        "hamming_distance": None, "is_visual_clone": False,
        "risk": "unknown", "note": "",
    }

    if not _DEPS_OK:
        base["note"] = "Pillow / ImageHash not installed — favicon check skipped."
        return base

    url = _normalize_url(url)

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

    best_brand, best_distance, best_domains = None, None, []
    for brand, entry in known_db.items():
        try:
            brand_hash = imagehash.hex_to_hash(entry["phash"])
        except (KeyError, ValueError):
            continue
        distance = scanned_hash - brand_hash
        if best_distance is None or distance < best_distance:
            best_brand, best_distance, best_domains = brand, distance, entry.get("domains", [])

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