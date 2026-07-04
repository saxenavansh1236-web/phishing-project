"""
whois_check.py
Looks up domain registration age. New domains are a strong phishing signal.
"""

import whois
from datetime import datetime, timezone


def get_domain_age_info(url):
    """
    Returns a dict with domain age + risk level.
    Fails gracefully (returns 'unknown') if WHOIS lookup fails or is blocked,
    since this should never crash a scan.
    """
    try:
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]
        domain = domain.replace("www.", "")

        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {"domain_age_days": None, "risk": "unknown", "registrar": None}

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation_date).days

        if age_days < 30:
            risk = "high"
        elif age_days < 180:
            risk = "medium"
        else:
            risk = "low"

        return {
            "domain_age_days": age_days,
            "risk": risk,
            "registrar": w.registrar,
            "creation_date": creation_date.strftime("%Y-%m-%d")
        }
    except Exception as e:
        return {"domain_age_days": None, "risk": "unknown", "registrar": None, "error": str(e)}