
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET = BASE_DIR / "results" / "unseen_test_dataset.csv"
MODEL_FILE = BASE_DIR / "results" / "realtime_model.joblib"

if not DATASET.exists():
    raise SystemExit(f"Test dataset not found: {DATASET}")

if not MODEL_FILE.exists():
    raise SystemExit(f"Model not found: {MODEL_FILE}")

bundle = joblib.load(MODEL_FILE)
model = bundle["model"]
features = bundle["features"]

df = pd.read_csv(DATASET)
df.columns = df.columns.str.strip()

required = features + ["label"]
missing = [col for col in required if col not in df.columns]
if missing:
    raise SystemExit(f"Missing columns: {missing}")

df = df[df["label"].isin(["normal", "abnormal"])].copy()
df[features] = df[features].apply(pd.to_numeric, errors="coerce")
df = df.dropna(subset=features + ["label"])

if df.empty:
    raise SystemExit("No valid labeled test samples found.")

# Isolation Forest: 1 = normal, -1 = anomaly
predictions = model.predict(df[features])
predicted_labels = [
    "normal" if prediction == 1 else "abnormal"
    for prediction in predictions
]

actual = df["label"]
print(f"Test samples: {len(df)}")
print(f"Actual label counts:\n{actual.value_counts()}")
print(f"Accuracy: {accuracy_score(actual, predicted_labels):.3f}")
print("\nConfusion matrix (normal, abnormal):")
print(confusion_matrix(
    actual, predicted_labels, labels=["normal", "abnormal"]
))
print("\nClassification report:")
print(classification_report(
    actual,
    predicted_labels,
    labels=["normal", "abnormal"],
    zero_division=0,
))
