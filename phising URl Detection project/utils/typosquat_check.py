"""
typosquat_check.py
Flags domains that closely resemble well-known brands (typosquatting),
e.g. "paypa1.com" instead of "paypal.com".
"""

import Levenshtein

# Extend this list with whatever brands you want to demo against
KNOWN_BRANDS = [
    "paypal.com", "google.com", "amazon.com", "microsoft.com",
    "apple.com", "facebook.com", "instagram.com", "netflix.com",
    "bankofamerica.com", "chase.com", "hdfcbank.com", "icicibank.com",
    "sbi.co.in", "whatsapp.com", "linkedin.com",
]


def check_typosquatting(url, max_distance=2):
    """
    Compares the domain in `url` against KNOWN_BRANDS using edit distance.
    A small distance (1-2 characters) that ISN'T an exact match
    is a strong typosquatting signal.
    """
    domain = url.replace("http://", "").replace("https://", "").split("/")[0]
    domain = domain.replace("www.", "")

    matches = []
    for brand in KNOWN_BRANDS:
        if domain == brand:
            continue  # exact match = legitimate brand domain, not typosquatting
        distance = Levenshtein.distance(domain, brand)
        if distance <= max_distance:
            matches.append({"brand": brand, "distance": distance})

    matches.sort(key=lambda m: m["distance"])

    if matches:
        return {
            "is_typosquat": True,
            "likely_target": matches[0]["brand"],
            "edit_distance": matches[0]["distance"],
        }
    return {"is_typosquat": False}