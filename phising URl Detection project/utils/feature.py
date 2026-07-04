from urllib.parse import urlparse

def extract_features(url):

    features = []

    # URL Length
    features.append(len(url))

    # Has @ symbol
    features.append(1 if '@' in url else 0)

    # Count dots
    features.append(url.count('.'))

    # HTTPS check
    features.append(1 if 'https' in url else 0)

    # Has hyphen
    features.append(1 if '-' in url else 0)

    return features
