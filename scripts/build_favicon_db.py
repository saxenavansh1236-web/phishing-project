"""
scripts/build_favicon_db.py

Run this ONCE, manually, from your own machine with normal internet
access, to build utils/known_favicons.json — the local database of
known-brand favicon perceptual hashes that favicon_check.py compares
scanned sites against.

This is intentionally a separate, offline step rather than something
the live Flask app does automatically, because:
  - it only needs to run when you add/update brands, not on every scan
  - it avoids the live app depending on a fixed list of "trusted" sites
    being reachable at request time
  - it makes the database auditable — you can open the JSON and see
    exactly which brands/domains are trusted as the "genuine" baseline

Usage:
    python scripts/build_favicon_db.py

Add more brands by extending the BRANDS list below with:
    ("Brand Display Name", "https://example.com", ["example.com", "www.example.com"])

The middle URL is where we fetch the REAL favicon from (should be the
brand's actual homepage); the domain list is what counts as "legitimate"
when favicon_check.py decides whether a match is a clone or the real site.
"""

import io
import json
import os
import re
import sys
from urllib.parse import urljoin

import requests

try:
    from PIL import Image
    import imagehash
except ImportError:
    print("Missing dependencies. Run: pip install Pillow imagehash")
    sys.exit(1)

HEADERS = {"User-Agent": "Mozilla/5.0 (PhishGuard-FaviconDBBuilder)"}
REQUEST_TIMEOUT = 8
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "utils", "known_favicons.json")

# Extend this list with whichever brands are most relevant to your
# threat model (e.g. banks common in your region, popular SaaS logins).
BRANDS = [
    ("PayPal",            "https://www.paypal.com",           ["paypal.com", "www.paypal.com"]),
    ("Google",            "https://www.google.com",           ["google.com", "www.google.com", "accounts.google.com"]),
    ("Microsoft",         "https://www.microsoft.com",        ["microsoft.com", "www.microsoft.com", "login.microsoftonline.com"]),
    ("Amazon",            "https://www.amazon.com",           ["amazon.com", "www.amazon.com"]),
    ("Apple",             "https://www.apple.com",            ["apple.com", "www.apple.com", "appleid.apple.com"]),
    ("Facebook",          "https://www.facebook.com",         ["facebook.com", "www.facebook.com"]),
    ("Instagram",         "https://www.instagram.com",        ["instagram.com", "www.instagram.com"]),
    ("Netflix",           "https://www.netflix.com",          ["netflix.com", "www.netflix.com"]),
    ("LinkedIn",          "https://www.linkedin.com",         ["linkedin.com", "www.linkedin.com"]),
    ("GitHub",            "https://www.github.com",           ["github.com", "www.github.com"]),
    ("State Bank of India","https://www.onlinesbi.sbi",       ["onlinesbi.sbi", "www.onlinesbi.sbi", "sbi.co.in"]),
    ("HDFC Bank",         "https://www.hdfcbank.com",         ["hdfcbank.com", "www.hdfcbank.com"]),
    ("ICICI Bank",        "https://www.icicibank.com",        ["icicibank.com", "www.icicibank.com"]),
    ("Axis Bank",         "https://www.axisbank.com",         ["axisbank.com", "www.axisbank.com"]),
    ("Dropbox",           "https://www.dropbox.com",          ["dropbox.com", "www.dropbox.com"]),
]


def find_favicon_url(page_url: str) -> str:
    try:
        resp = requests.get(page_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        html = resp.text[:200_000]
        for match in re.finditer(
            r'<link[^>]+rel=["\'](?:shortcut icon|icon|apple-touch-icon)["\'][^>]*>',
            html,
            re.IGNORECASE,
        ):
            href_match = re.search(r'href=["\']([^"\']+)["\']', match.group(0), re.IGNORECASE)
            if href_match:
                return urljoin(page_url, href_match.group(1))
    except requests.exceptions.RequestException:
        pass
    return urljoin(page_url, "/favicon.ico")


def hash_favicon(favicon_url: str):
    resp = requests.get(favicon_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    image = Image.open(io.BytesIO(resp.content)).convert("RGBA")
    return str(imagehash.phash(image))


def main():
    db = {}
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
            db = json.load(f)

    for brand, homepage, domains in BRANDS:
        print(f"Processing {brand}...", end=" ")
        try:
            favicon_url = find_favicon_url(homepage)
            phash = hash_favicon(favicon_url)
            db[brand] = {
                "phash": phash,
                "domains": domains,
                "source_favicon": favicon_url,
            }
            print(f"OK ({phash})")
        except Exception as e:
            print(f"FAILED ({e})")

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)

    print(f"\nSaved {len(db)} brand(s) to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()