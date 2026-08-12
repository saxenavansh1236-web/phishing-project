from urllib.parse import urlparse

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc   # e.g. "meet.google.com" — excludes path/query
    path_and_query = parsed.path + '?' + parsed.query

    features = []

    # URL Length (kept as full URL — length is a legitimate whole-URL signal)
    features.append(len(url))

    # Has @ symbol (kept as full URL — @ anywhere in a URL is genuinely suspicious,
    # since it's a classic trick to hide the real destination before the @)
    features.append(1 if '@' in url else 0)

    # Count dots — domain only (subdomain depth is the real phishing signal,
    # e.g. paypal.com.verify-login.xyz — dots in a path are meaningless)
    features.append(domain.count('.'))

    # HTTPS check — actual scheme, not a substring search
    features.append(1 if parsed.scheme == 'https' else 0)

    # Has hyphen — domain only (this is the exact bug that flagged your Meet link)
    features.append(1 if '-' in domain else 0)

    return features
