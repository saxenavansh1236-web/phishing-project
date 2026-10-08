"""
explain.py -- human-readable reasons for why a URL was flagged.

Driven by FEATURE_NAMES from utils/features.py, so the explanation rules can
never fall out of step with the features the model was trained on. Each rule
says when a feature value looks suspicious and what to tell the user; the
reasons shown are the suspicious features ranked by the model's global
feature importance.
"""
from utils.features import FEATURE_NAMES

# name -> (is_suspicious(value), explanation)
RULES = {
    "url_length": (lambda v, f: v > 45,
        "Domain/address is unusually long, a common phishing obfuscation tactic"),
    "has_at_symbol": (lambda v, f: v == 1,
        "URL contains an '@' before the domain, which can hide the real destination"),
    "dot_count": (lambda v, f: v >= 4,
        "Domain has an unusually high number of dots/subdomains"),
    "has_https": (lambda v, f: v == 0,
        "URL does not use HTTPS, meaning the connection isn't encrypted"),
    "has_hyphen": (lambda v, f: v == 1,
        "Domain contains a hyphen, often used to mimic real brand names (e.g. paypal-secure.com)"),
    "hyphen_count": (lambda v, f: v >= 3,
        "Domain contains many hyphens, typical of auto-generated phishing domains"),
    "digit_ratio": (lambda v, f: v > 0.25,
        "Domain contains an unusually high share of digits"),
    # entropy grows with length, so a long readable name (paypal-login-security) also scores
    # high. Only call a domain "random-looking" when nothing word-like explains it.
    "domain_entropy": (lambda v, f: v > 3.3 and f["hyphen_count"] == 0
                       and f["host_keyword_count"] == 0 and f["brand_in_host_mismatch"] == 0,
        "Domain name looks randomly generated (high character entropy)"),
    "subdomain_count": (lambda v, f: v >= 3,
        "Domain hides behind many nested subdomains (e.g. paypal.com.verify.example.xyz)"),
    "suspicious_tld": (lambda v, f: v == 1,
        "Domain uses a top-level domain that is heavily abused for phishing"),
    "is_ip_host": (lambda v, f: v == 1,
        "URL uses a raw IP address instead of a domain name"),
    "has_punycode": (lambda v, f: v == 1,
        "Domain uses punycode (xn--), which can disguise lookalike characters"),
    "host_keyword_count": (lambda v, f: v >= 1,
        "Domain contains sensitive keywords such as login, secure or verify"),
    "has_nonstandard_port": (lambda v, f: v == 1,
        "URL uses an unusual network port"),
    "brand_in_host_mismatch": (lambda v, f: v == 1,
        "Domain contains a well-known brand name but is not that brand's real domain"),
}

# when the specific rule fires, hide its more generic twin
SUPERSEDES = {"hyphen_count": "has_hyphen", "subdomain_count": "dot_count"}


def explain_prediction(model, feature_vector, top_n=4):
    """
    Returns [{feature, explanation, weight}, ...] for the suspicious features
    that most likely drove THIS prediction, strongest (by importance) first.
    """
    values = list(feature_vector)
    feats = dict(zip(FEATURE_NAMES, values))
    importances = getattr(model, "feature_importances_", None)
    if importances is None:
        importances = [1.0] * len(FEATURE_NAMES)

    triggered = {}
    for i, name in enumerate(FEATURE_NAMES):
        if i >= len(values) or i >= len(importances) or name not in RULES:
            continue
        is_suspicious, _ = RULES[name]
        if is_suspicious(values[i], feats):
            triggered[name] = float(importances[i])

    for specific, generic in SUPERSEDES.items():
        if specific in triggered:
            triggered.pop(generic, None)

    ranked = sorted(triggered.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    results = [{"feature": n, "explanation": RULES[n][1], "weight": round(w, 3)}
               for n, w in ranked]

    if not results:
        results = [{
            "feature": "model",
            "explanation": "The overall combination of domain characteristics resembles known phishing URLs",
            "weight": 0.0,
        }]
    return results