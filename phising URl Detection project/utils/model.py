"""
model.py -- Trains and evaluates the phishing-detection model.

* Features come from utils/features.py (origin-scoped, FEATURE_NAMES).
* Several model families are compared with cross-validation on the TRAIN split;
  the best one that supports feature importances (needed for explainability)
  is deployed and then scored ONCE on a held-out test split.
* Train/test (and the CV folds) are split by registered domain, so URLs from
  the same domain never appear on both sides -- otherwise metrics are inflated.
* Everything is saved to model_metrics.json (incl. the comparison table).

Usage:  python model.py          (reads dataset.csv with columns: url,label)
        label: 1 = phishing, 0 = legitimate
Build a real dataset first:  python scripts/build_dataset.py --help
"""
import json
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import (StratifiedGroupKFold, StratifiedKFold,
                                     cross_val_score, train_test_split)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from utils.features import FEATURE_NAMES, extract_features, get_registered_domain

SEED = 42

# ── 1. Load & clean ────────────────────────────────────────────
data = pd.read_csv("dataset.csv")
if not {"url", "label"} <= set(data.columns):
    sys.exit("dataset.csv must have the columns: url,label")

data = data.dropna(subset=["url", "label"]).drop_duplicates(subset=["url"]).reset_index(drop=True)
data["label"] = data["label"].astype(int)

if len(data) < 200:
    print(f"⚠️  WARNING: dataset.csv only has {len(data)} rows. Metrics from a dataset this small "
          f"are not statistically meaningful. Run scripts/build_dataset.py for a real one.")

# ── 2. Features ────────────────────────────────────────────────
rows, labels, groups, skipped = [], [], [], 0
for url, label in zip(data["url"], data["label"]):
    try:
        rows.append(extract_features(url))
        groups.append(get_registered_domain(url) or url)
        labels.append(label)
    except Exception:
        skipped += 1
X = np.array(rows, dtype=float)
y = np.array(labels)
groups = np.array(groups)
if skipped:
    print(f"Skipped {skipped} rows whose features could not be extracted.")

counts = np.bincount(y, minlength=2)
if counts.min() < 2:
    sys.exit(f"Need at least 2 examples of each class (phishing={counts[1]}, safe={counts[0]}).")

# ── 3. Train/test split, grouped by registered domain ──────────
try:
    n_folds = 5 if len(y) >= 50 else 2
    splitter = StratifiedGroupKFold(n_splits=n_folds, shuffle=True, random_state=SEED)
    train_idx, test_idx = next(splitter.split(X, y, groups))
    split_kind = "grouped by domain"
except ValueError:
    train_idx, test_idx = train_test_split(np.arange(len(y)), test_size=0.2,
                                           random_state=SEED, stratify=y)
    split_kind = "stratified random (too little data to group)"

X_train, X_test, y_train, y_test = X[train_idx], X[test_idx], y[train_idx], y[test_idx]
g_train = groups[train_idx]

if len(set(y_test)) < 2:
    print("⚠️  Test split contains only one class; metrics will be unreliable.")

# ── 4. Compare models (cross-validation on TRAIN only) ─────────
candidates = {
    "RandomForest": RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                           n_jobs=-1, random_state=SEED),
    "GradientBoosting": GradientBoostingClassifier(random_state=SEED),
    "DecisionTree": DecisionTreeClassifier(max_depth=8, class_weight="balanced", random_state=SEED),
    "LogisticRegression": make_pipeline(StandardScaler(),
                                        LogisticRegression(max_iter=2000, class_weight="balanced")),
}

min_train_class = int(np.bincount(y_train, minlength=2).min())
n_cv = min(5, min_train_class)
cv = None
if n_cv >= 2:
    try:
        cv = list(StratifiedGroupKFold(n_splits=n_cv, shuffle=True, random_state=SEED)
                  .split(X_train, y_train, g_train))
    except ValueError:
        cv = list(StratifiedKFold(n_splits=n_cv, shuffle=True, random_state=SEED).split(X_train, y_train))

comparison, fitted = [], {}
for name, est in candidates.items():
    cv_mean = cv_std = None
    if cv:
        scores = cross_val_score(est, X_train, y_train, cv=cv, scoring="f1")
        cv_mean, cv_std = float(scores.mean()), float(scores.std())
    est.fit(X_train, y_train)
    pred = est.predict(X_test)
    proba = est.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, proba) if len(set(y_test)) == 2 else float("nan")
    comparison.append({
        "model": name,
        "cv_f1_mean": None if cv_mean is None else round(cv_mean, 4),
        "cv_f1_std": None if cv_std is None else round(cv_std, 4),
        "test_accuracy": round(accuracy_score(y_test, pred), 4),
        "test_f1": round(f1_score(y_test, pred, zero_division=0), 4),
        "test_roc_auc": None if np.isnan(auc) else round(auc, 4),
        "explainable": hasattr(est, "feature_importances_"),
    })
    fitted[name] = est

# Deploy the best model that exposes feature_importances_ (the app's explainer needs it).
# Selection uses CV on the train split, never the test split.
def _key(row):
    return (row["cv_f1_mean"] if row["cv_f1_mean"] is not None else row["test_f1"])

explainable = [r for r in comparison if r["explainable"]]
best = max(explainable, key=_key)
chosen_name = best["model"]
model = fitted[chosen_name]

# ── 5. Final evaluation on the held-out test split ─────────────
y_pred = model.predict(X_test)
proba = model.predict_proba(X_test)[:, 1]
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0)
recall = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)
auc = roc_auc_score(y_test, proba) if len(set(y_test)) == 2 else None
cm = confusion_matrix(y_test, y_pred, labels=[0, 1]).tolist()

print("=" * 64)
print(f"Dataset: {len(y)} rows  (phishing={int(counts[1])}, safe={int(counts[0])})")
print(f"Split  : {len(y_train)} train / {len(y_test)} test  [{split_kind}]")
print("-" * 64)
print(f"{'Model':<20}{'CV F1':>14}{'Test F1':>10}{'Test AUC':>10}")
for r in comparison:
    cvs = "n/a" if r["cv_f1_mean"] is None else f"{r['cv_f1_mean']:.3f}±{r['cv_f1_std']:.3f}"
    mark = "  <- deployed" if r["model"] == chosen_name else ""
    print(f"{r['model']:<20}{cvs:>14}{r['test_f1']:>10.3f}{str(r['test_roc_auc']):>10}{mark}")
print("-" * 64)
print(f"Deployed model   : {chosen_name}")
print(f"Accuracy         : {accuracy:.4f}")
print(f"Precision        : {precision:.4f}")
print(f"Recall           : {recall:.4f}")
print(f"F1-score         : {f1:.4f}")
print(f"ROC AUC          : {auc if auc is None else round(auc, 4)}")
print(f"Confusion matrix : {cm}  (format: [[TN, FP], [FN, TP]])")
print("-" * 64)
print(classification_report(y_test, y_pred, zero_division=0))
importances = dict(sorted(zip(FEATURE_NAMES, map(float, model.feature_importances_)),
                          key=lambda kv: kv[1], reverse=True))
print("Top features:")
for n, w in list(importances.items())[:8]:
    print(f"  {n:<24}{w:.3f}")
print("=" * 64)

# ── 6. Save ────────────────────────────────────────────────────
joblib.dump(model, "phishing_model.pkl")

metrics = {
    "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "deployed_model": chosen_name,
    "dataset_size": int(len(y)),
    "class_counts": {"safe": int(counts[0]), "phishing": int(counts[1])},
    "train_size": int(len(y_train)),
    "test_size": int(len(y_test)),
    "split": split_kind,
    "accuracy": round(accuracy, 4),
    "precision": round(precision, 4),
    "recall": round(recall, 4),
    "f1_score": round(f1, 4),
    "roc_auc": None if auc is None else round(auc, 4),
    "confusion_matrix": cm,
    "feature_names": FEATURE_NAMES,
    "feature_importances": {k: round(v, 4) for k, v in importances.items()},
    "model_comparison": comparison,
}
with open("model_metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)

print("Model trained — saved phishing_model.pkl and model_metrics.json")