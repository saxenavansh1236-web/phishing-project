#!/usr/bin/env python3
"""
scripts/stress_test.py -- does the deployed MODEL over-flag obscure legitimate sites?

The training set's legitimate class is Tranco ranks 1-100,000 (short, famous
domains). Here we score domains from a LESS popular part of the list (default
ranks 100,001-1,000,000) that the model has never seen, and report how often the
ML model alone calls them phishing, split by domain length. If long names are
flagged far more often, the model learned "long = phishing" (a dataset quirk) --
exactly why the app combines the model with other evidence (utils/risk.py).

    python scripts/stress_test.py                    # downloads Tranco, samples 3000
    python scripts/stress_test.py --domains-file my_legit_domains.txt
"""
import argparse
import io
import os
import random
import sys
import zipfile

import joblib
import numpy as np
import pandas as pd
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.features import FEATURE_NAMES, extract_features  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--n", type=int, default=3000, help="domains to sample")
ap.add_argument("--from-rank", type=int, default=100_001)
ap.add_argument("--domains-file", help="one legitimate domain per line (skips the download)")
ap.add_argument("--seed", type=int, default=42)
args = ap.parse_args()
rnd = random.Random(args.seed)

if args.domains_file:
    with open(args.domains_file, encoding="utf-8", errors="ignore") as f:
        domains = [l.strip().lower() for l in f if l.strip()]
else:
    r = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=180)
    r.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(r.content))
    with z.open(z.namelist()[0]) as f:
        df = pd.read_csv(f, header=None, names=["rank", "domain"])
    domains = df[df["rank"] >= args.from_rank]["domain"].astype(str).str.lower().tolist()
    print(f"Tranco: {len(domains)} domains at rank >= {args.from_rank}")

rnd.shuffle(domains)
domains = domains[: args.n]

model = joblib.load("phishing_model.pkl")
urls = [f"https://{d}" for d in domains]
X = np.array([extract_features(u) for u in urls], dtype=float)
flagged = model.predict(X) == 1
host_len = np.array([len(d) for d in domains])

print(f"\nObscure legitimate domains scored: {len(domains)}")
print(f"Overall false-positive rate of the ML model alone: {flagged.mean():.1%}\n")
print(f"{'Domain length':<18}{'count':>7}{'flagged as phishing':>24}")
for lo, hi in [(0, 10), (11, 15), (16, 20), (21, 30), (31, 999)]:
    m = (host_len >= lo) & (host_len <= hi)
    if m.sum():
        print(f"{f'{lo}-{hi} chars':<18}{int(m.sum()):>7}{flagged[m].mean():>23.1%}")

print("\nMost-flagged examples:")
proba = model.predict_proba(X)[:, 1]
for i in np.argsort(-proba)[:10]:
    print(f"  {proba[i]:.0%}  {domains[i]}")
print("\nIf the rate climbs steeply with length, the model is leaning on length. The app's combined\n"
      "risk score (clean VirusTotal, old domain, valid SSL) is what protects users from those flags.")