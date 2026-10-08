"""
utils/features.py -- URL feature extraction (ORIGIN-scoped).

The model judges the ORIGIN of a URL (scheme + host [+ port]) -- never its path
or query string. Reasons:
  * Training data for legitimate sites (Tranco) only contains domains, so path
    features would be constant in training and give the model nothing to learn.
  * Path-based features cause false positives on legitimate links (the old
    Google Meet bug: meet.google.com/tbj-dudh-fex). Path-level phishing signals
    are covered elsewhere: page content analysis and VirusTotal.

FEATURE_NAMES is the single source of truth: model.py, explain.py and app.py
all import it, so the three can never drift apart. If you change this file you
MUST re-run `python model.py`.
"""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse

import tldextract

# offline: bundled public-suffix snapshot, never downloads a list at runtime
_tld = tldextract.TLDExtract(suffix_list_urls=())

# TLDs with consistently high abuse rates in public phishing/malware statistics.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "zip", "mov",
    "country", "kim", "loan", "men", "review", "stream", "download", "racing",
    "party", "cricket", "science", "date", "faith", "accountant", "support",
    "rest", "icu", "buzz", "monster", "cyou", "cfd", "sbs", "shop", "live",
}

KEYWORDS = (
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "confirm", "password", "wallet", "webscr", "billing", "suspended",
    "unlock", "recover", "validate", "auth", "support", "alert",
)

# brand token -> its legitimate registered domains
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "gstatic.com", "googleusercontent.com", "google.co.in"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "whatsapp": {"whatsapp.com"},
    "paytm": {"paytm.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com"},
}

FEATURE_NAMES = [
    "url_length",             # length of scheme://host[:port]
    "has_at_symbol",          # '@' inside the authority (user@host trick)
    "dot_count",              # dots in the host
    "has_https",              # real scheme
    "has_hyphen",             # hyphen in host
    "hyphen_count",
    "digit_ratio",            # digits / host length
    "domain_entropy",         # Shannon entropy of the registrable label
    "subdomain_count",
    "suspicious_tld",
    "is_ip_host",
    "has_punycode",           # xn-- labels (IDN lookalikes)
    "host_keyword_count",     # login/verify/secure... inside the host
    "has_nonstandard_port",
    "brand_in_host_mismatch", # brand name in host, but not the brand's domain
]


def _registered(ext):
    """registrable domain; works on old and new tldextract (property was renamed)."""
    if hasattr(type(ext), "top_domain_under_public_suffix"):
        return ext.top_domain_under_public_suffix
    return ext.registered_domain


def _entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _parse(url):
    raw = (url or "").strip()
    target = raw if "://" in raw else "http://" + raw   # bare domain => treated as http
    try:
        return urlparse(target)
    except ValueError:
        return urlparse("http://invalid.invalid")


def get_registered_domain(url):
    """e.g. 'https://login.example.co.uk/x' -> 'example.co.uk' (used for grouped splits)."""
    return _registered(_tld(_parse(url).hostname or "")).lower()


def extract_features(url):
    parsed = _parse(url)
    scheme = parsed.scheme
    netloc = parsed.netloc
    host = (parsed.hostname or "").lower()
    ext = _tld(host)
    registered = _registered(ext).lower()

    try:
        port = parsed.port
        bad_port = False
    except ValueError:
        port, bad_port = None, True

    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        is_ip = 0

    sub = ext.subdomain.lower()
    if sub == "www":
        sub = ""
    elif sub.startswith("www."):
        sub = sub[4:]
    subdomain_count = len(sub.split(".")) if sub else 0

    tld_last = ext.suffix.split(".")[-1].lower() if ext.suffix else ""
    tokens = re.split(r"[.\-_]", host)
    brand_mismatch = 0
    for brand, domains in BRAND_DOMAINS.items():
        present = (brand in tokens) if len(brand) <= 4 else (brand in host)
        if present and registered not in domains:
            brand_mismatch = 1
            break

    features = [
        len(f"{scheme}://{netloc}"),
        1 if "@" in netloc else 0,
        host.count("."),
        1 if scheme == "https" else 0,
        1 if "-" in host else 0,
        host.count("-"),
        round(sum(ch.isdigit() for ch in host) / max(len(host), 1), 4),
        round(_entropy(ext.domain.lower()), 4),
        subdomain_count,
        1 if tld_last in SUSPICIOUS_TLDS else 0,
        is_ip,
        1 if "xn--" in host else 0,
        sum(1 for k in KEYWORDS if k in host),
        1 if (bad_port or port not in (None, 80, 443)) else 0,
        brand_mismatch,
    ]
    assert len(features) == len(FEATURE_NAMES)
    return features


if __name__ == "__main__":
    for u in ["https://meet.google.com/tbj-dudh-fex",
              "http://paypal-login-security.xyz",
              "http://192.168.1.5:8080/login",
              "http://paypal.com@evil.example.net/",
              "https://xn--pypal-4ve.com"]:
        print(u, "->", dict(zip(FEATURE_NAMES, extract_features(u))))