#!/usr/bin/env python3
"""
scripts/ablation.py -- which features is the model REALLY relying on?

Retrains GradientBoosting with each feature removed (and a few groups removed),
using the SAME domain-grouped train/test split as model.py, and shows how the
test scores change. It never touches the deployed phishing_model.pkl.

Why: if one feature carries most of the importance (e.g. url_length), the model
may be learning a quirk of how the dataset was built instead of real phishing
behaviour. If dropping it barely changes the score, the model is robust. If the
score collapses, the model leans on it heavily.

Run from the project root:   python scripts/ablation.py
"""
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, f1_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.features import FEATURE_NAMES, extract_features, get_registered_domain  # noqa: E402

SEED = 42
data = (pd.read_csv("dataset.csv").dropna(subset=["url", "label"])
        .drop_duplicates(subset=["url"]).reset_index(drop=True))
X = np.array([extract_features(u) for u in data["url"]], dtype=float)
y = data["label"].astype(int).values
groups = np.array([get_registered_domain(u) or u for u in data["url"]])

tr, te = next(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED).split(X, y, groups))
idx = {n: i for i, n in enumerate(FEATURE_NAMES)}


def evaluate(drop=()):
    cols = [i for n, i in idx.items() if n not in drop]
    m = GradientBoostingClassifier(random_state=SEED).fit(X[tr][:, cols], y[tr])
    pred = m.predict(X[te][:, cols])
    proba = m.predict_proba(X[te][:, cols])[:, 1]
    return {
        "acc": accuracy_score(y[te], pred),
        "f1": f1_score(y[te], pred),
        "recall": recall_score(y[te], pred),
        "auc": roc_auc_score(y[te], proba),
    }


base = evaluate()
rows = []
for name in FEATURE_NAMES:
    r = evaluate(drop=(name,))
    rows.append((f"- {name}", r))

GROUPS = {
    "- url_length + dot_count + subdomain_count (length/size cues)": ("url_length", "dot_count", "subdomain_count"),
    "- digit_ratio + domain_entropy + hyphen_count (name-shape cues)": ("digit_ratio", "domain_entropy", "hyphen_count"),
}
for label, cols in GROUPS.items():
    rows.append((label, evaluate(drop=cols)))

print(f"\nBaseline (all {len(FEATURE_NAMES)} features):  "
      f"F1={base['f1']:.3f}  AUC={base['auc']:.3f}  recall={base['recall']:.3f}  acc={base['acc']:.3f}\n")
print(f"{'Removed':<62}{'F1':>7}{'dF1':>8}{'AUC':>8}{'dAUC':>8}")
for label, r in sorted(rows, key=lambda t: t[1]["f1"]):
    print(f"{label:<62}{r['f1']:>7.3f}{r['f1'] - base['f1']:>+8.3f}{r['auc']:>8.3f}{r['auc'] - base['auc']:>+8.3f}")
print("\nReading it: a big negative dF1 means the model depends heavily on what you removed;\n"
      "~0 means that feature adds little (or another feature covers for it).")