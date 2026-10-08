#!/usr/bin/env python3
"""
scripts/build_dataset.py -- builds dataset.csv (url,label) for model.py.

  phishing (label 1): PhishTank verified-online feed + OpenPhish community feed
  legitimate (label 0): Tranco top sites list

Run from the project root, from a machine with normal internet access:

    python scripts/build_dataset.py --username yourname
    python scripts/build_dataset.py --username yourname --phishtank-key YOUR_KEY --per-class 8000

PhishTank limits anonymous downloads to a few per day; a free application key
(https://phishtank.org/api_info.php) removes that. You can also supply your own
files with --phish-file / --legit-file (one URL or domain per line).

IMPORTANT design choices (read before quoting accuracy numbers)
  * Every URL is reduced to its ORIGIN (scheme://host/). Tranco has no paths, so
    keeping phishing paths would let the model "cheat" by learning
    "has a path => phishing". utils/features.py is origin-scoped to match.
  * Phishing hosts that belong to a top-10k popular domain (e.g. a phish hosted
    on a big file-sharing site) are dropped: the origin alone is legitimate and
    would otherwise create contradictory labels.
  * Tranco only lists registrable domains, so ~60% of legit rows get a common
    subdomain prefix (www, mail, accounts ...). This is SYNTHETIC. It stops the
    model from learning "has a subdomain => phishing". Real legit URLs from other
    sources (e.g. a Kaggle dataset passed via --legit-file) are better.
"""
import argparse
import io
import os
import random
import sys
import zipfile
from urllib.parse import urlparse

import pandas as pd
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.features import get_registered_domain  # noqa: E402

COMMON_SUBDOMAINS = ["www", "mail", "accounts", "login", "secure", "support", "docs", "app",
                     "blog", "shop", "m", "api", "portal", "my", "help", "store", "id", "web"]


def to_origin(url):
    url = url.strip()
    if not url:
        return None
    if "://" not in url:
        url = "http://" + url
    try:
        p = urlparse(url)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc.lower()}/"


def fetch_phishtank(username, key):
    url = "http://data.phishtank.com/data/" + (f"{key}/" if key else "") + "online-valid.csv"
    r = requests.get(url, headers={"User-Agent": f"phishtank/{username}"}, timeout=180)
    r.raise_for_status()
    return pd.read_csv(io.StringIO(r.text))["url"].dropna().astype(str).tolist()


def fetch_openphish():
    r = requests.get("https://openphish.com/feed.txt", timeout=60,
                     headers={"User-Agent": "PhishGuard-dataset-builder"})
    r.raise_for_status()
    return [l.strip() for l in r.text.splitlines() if l.strip()]


def fetch_tranco(n):
    r = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=180)   # redirects to the daily list
    r.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(r.content))
    with z.open(z.namelist()[0]) as f:
        df = pd.read_csv(f, header=None, names=["rank", "domain"], nrows=n)
    return df["domain"].astype(str).tolist()


def read_lines(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--username", default="phishguard-student", help="used in the PhishTank User-Agent")
    ap.add_argument("--phishtank-key", default=None)
    ap.add_argument("--per-class", type=int, default=5000)
    ap.add_argument("--phish-file", help="extra phishing URLs, one per line")
    ap.add_argument("--legit-file", help="legit URLs/domains, one per line (replaces Tranco)")
    ap.add_argument("--out", default="dataset.csv")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    rnd = random.Random(args.seed)

    # ── phishing ──
    phish_raw = []
    for name, fn in (("PhishTank", lambda: fetch_phishtank(args.username, args.phishtank_key)),
                     ("OpenPhish", fetch_openphish)):
        try:
            got = fn()
            print(f"{name}: {len(got)} URLs")
            phish_raw += got
        except Exception as e:
            print(f"{name}: FAILED ({e})")
    if args.phish_file:
        extra = read_lines(args.phish_file)
        print(f"{args.phish_file}: {len(extra)} URLs")
        phish_raw += extra
    if not phish_raw:
        sys.exit("No phishing URLs obtained. Get a PhishTank key or pass --phish-file.")

    # ── legitimate ──
    if args.legit_file:
        legit_domains = read_lines(args.legit_file)
        print(f"{args.legit_file}: {len(legit_domains)} entries")
    else:
        legit_domains = fetch_tranco(100_000)
        print(f"Tranco: using top {len(legit_domains)} domains")
    top_popular = {get_registered_domain("http://" + d) for d in legit_domains[:10_000]}

    # ── clean phishing ──
    phish = {}
    for u in phish_raw:
        o = to_origin(u)
        if not o:
            continue
        reg = get_registered_domain(o)
        if not reg or reg in top_popular:
            continue
        phish[o] = 1
    phish = list(phish)

    # ── build legit ──
    legit = {}
    pool = legit_domains[:]
    rnd.shuffle(pool)
    for d in pool:
        if "://" in d:                       # a full URL from --legit-file
            o = to_origin(d)
        else:
            host = d.lower().strip(".")
            r = rnd.random()
            if r < 0.40:
                prefix = ""
            elif r < 0.65:
                prefix = "www."
            else:
                prefix = rnd.choice(COMMON_SUBDOMAINS) + "."
            o = to_origin("https://" + prefix + host)
        if o:
            legit[o] = 0
        if len(legit) >= args.per_class * 2:
            break
    legit = list(legit)

    n = min(args.per_class, len(phish), len(legit))
    rnd.shuffle(phish)
    rnd.shuffle(legit)
    rows = [(u, 1) for u in phish[:n]] + [(u, 0) for u in legit[:n]]
    rnd.shuffle(rows)

    if os.path.exists(args.out):
        backup = args.out.replace(".csv", ".backup.csv")
        os.replace(args.out, backup)
        print(f"Existing {args.out} moved to {backup}")
    pd.DataFrame(rows, columns=["url", "label"]).to_csv(args.out, index=False)
    print(f"\nWrote {args.out}: {len(rows)} rows ({n} phishing / {n} legitimate).")
    print("Next: python model.py")


if __name__ == "__main__":
    main()