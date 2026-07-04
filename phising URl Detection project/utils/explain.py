"""
explain.py
Generates human-readable reasons for why a URL was flagged,
based on the SAME 5 features your model is trained on in feature.py:

  index 0 -> URL length
  index 1 -> has '@' symbol
  index 2 -> dot count
  index 3 -> has 'https'
  index 4 -> has hyphen
"""

import numpy as np

# Must match the exact order features.append(...) happens in utils/feature.py
FEATURE_NAMES = [
    "url_length",
    "has_at_symbol",
    "dot_count",
    "has_https",
    "has_hyphen",
]

# How to explain each feature IF it looks suspicious for that URL
FEATURE_EXPLANATIONS = {
    "url_length": "URL is unusually long, a common phishing obfuscation tactic",
    "has_at_symbol": "URL contains an '@' symbol, which can be used to hide the real destination",
    "dot_count": "URL has an unusually high number of subdomains/dots",
    "has_https": "URL does not use HTTPS, meaning the connection isn't encrypted",
    "has_hyphen": "Domain contains a hyphen, often used to mimic real brand names (e.g. paypal-secure.com)",
}


def explain_prediction(model, feature_vector, top_n=4):
    """
    model: your loaded phishing_model.pkl (RandomForestClassifier)
    feature_vector: the exact list returned by extract_features(url)
    Returns a list of dicts: [{feature, explanation, weight}, ...]
    for the features that most likely drove THIS prediction toward phishing.
    """
    feature_vector = list(feature_vector)
    importances = model.feature_importances_  # global importance per feature, from training

    scored = []
    for i, name in enumerate(FEATURE_NAMES):
        if i >= len(feature_vector) or i >= len(importances):
            continue
        value = feature_vector[i]
        weight = importances[i]

        # Decide if THIS url's value for this feature looks suspicious
        suspicious = 0
        if name == "url_length" and value > 75:
            suspicious = 1
        elif name == "has_at_symbol" and value == 1:
            suspicious = 1
        elif name == "dot_count" and value >= 4:
            suspicious = 1
        elif name == "has_https" and value == 0:
            suspicious = 1
        elif name == "has_hyphen" and value == 1:
            suspicious = 1

        if suspicious:
            scored.append((name, weight))

    scored.sort(key=lambda x: x[1], reverse=True)

    results = []
    for name, weight in scored[:top_n]:
        results.append({
            "feature": name,
            "explanation": FEATURE_EXPLANATIONS[name],
            "weight": round(float(weight), 3)
        })
    return results