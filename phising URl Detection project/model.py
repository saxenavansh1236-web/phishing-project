"""
model.py -- Trains the phishing-detection model and saves accuracy,
precision, recall, and F1-score alongside the trained model so the
README (and admin panel, if wired up later) can report real numbers
instead of an unverified claim.
"""

import json
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)
import joblib

from utils.features import extract_features

# Load dataset
data = pd.read_csv("dataset.csv")

if len(data) < 20:
    print(
        f"⚠️  WARNING: dataset.csv only has {len(data)} rows. Metrics "
        f"computed from a dataset this small are not statistically "
        f"meaningful — treat any numbers below as illustrative only, "
        f"not a real accuracy claim. Add more labeled URLs before "
        f"quoting these numbers anywhere (README, resume, etc.)."
    )

# Extract features
X = data['url'].apply(extract_features).tolist()

# Labels
y = data['label']

# Train-test split
# stratify=y keeps the same phishing/safe ratio in both train and test
# splits — important on a small/imbalanced dataset so the test set
# isn't accidentally all-one-class.
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train model
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# Evaluate on the held-out test set
y_pred = model.predict(X_test)

accuracy  = accuracy_score(y_test, y_pred)
# zero_division=0 avoids a crash/warning if a class has no predicted
# samples at all, which is common on very small test sets.
precision = precision_score(y_test, y_pred, zero_division=0)
recall    = recall_score(y_test, y_pred, zero_division=0)
f1        = f1_score(y_test, y_pred, zero_division=0)
cm        = confusion_matrix(y_test, y_pred).tolist()
report    = classification_report(y_test, y_pred, zero_division=0)

print("=" * 50)
print("Model Evaluation (on held-out test set)")
print("=" * 50)
print(f"Dataset size     : {len(data)} rows")
print(f"Train / Test split: {len(X_train)} / {len(X_test)}")
print(f"Accuracy         : {accuracy:.4f}")
print(f"Precision        : {precision:.4f}")
print(f"Recall           : {recall:.4f}")
print(f"F1-score         : {f1:.4f}")
print(f"Confusion matrix : {cm}  (format: [[TN, FP], [FN, TP]])")
print("-" * 50)
print(report)
print("=" * 50)

# Save model
joblib.dump(model, "phishing_model.pkl")

# Save metrics to a JSON file so they can be read elsewhere (README,
# admin panel, a badge, etc.) without re-running training.
metrics = {
    "dataset_size": len(data),
    "train_size": len(X_train),
    "test_size": len(X_test),
    "accuracy": round(accuracy, 4),
    "precision": round(precision, 4),
    "recall": round(recall, 4),
    "f1_score": round(f1, 4),
    "confusion_matrix": cm,
}
with open("model_metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)

print("Model Trained Successfully — metrics saved to model_metrics.json")
