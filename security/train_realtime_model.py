
import pandas as pd
import numpy as np
import joblib

from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
)

# ==================================================
# CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATASET = BASE_DIR / "results" / "realtime_dataset_v4.csv"
MODEL_FILE = BASE_DIR / "results" / "realtime_model_v2.joblib"

FEATURES = [
    "packets",
    "total_bytes",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "duration",
    "packets_per_second",
    "client_to_server",
    "server_to_client",
]

RANDOM_STATE = 42
TEST_SIZE = 0.25

# ==================================================
# LOAD AND VALIDATE DATASET
# ==================================================

if not DATASET.exists():
    raise SystemExit(f"Dataset not found: {DATASET}")

df = pd.read_csv(DATASET)

required_columns = FEATURES + ["label", "run_id", "trial_id"]
missing_columns = [
    col for col in required_columns if col not in df.columns
]

if missing_columns:
    raise SystemExit(
        f"Missing required columns: {missing_columns}"
    )

df = df[df["label"].isin(["normal", "abnormal"])].copy()

# Convert features to numeric and remove invalid observations.
df[FEATURES] = df[FEATURES].apply(
    pd.to_numeric, errors="coerce"
)

df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna(
    subset=FEATURES + ["label", "run_id", "trial_id"]
)

if df["trial_id"].duplicated().any():
    raise SystemExit(
        "Duplicate trial IDs found. Resolve them before training."
    )

if (df[FEATURES] < 0).any().any():
    raise SystemExit(
        "Negative feature values found. Inspect the dataset."
    )

if df["run_id"].nunique() < 4:
    raise SystemExit(
        "At least four collection sessions are required "
        "for this session-aware split."
    )

print("=" * 60)
print("TLS TRAFFIC ANOMALY DETECTION - MODEL TRAINING")
print("=" * 60)

print("\nDataset:", DATASET)
print("Valid samples:", len(df))
print("Collection sessions:", df["run_id"].nunique())
print("Unique trials:", df["trial_id"].nunique())

print("\nLabel counts:")
print(df["label"].value_counts().to_string())

print("\nScenario counts:")
print(df.groupby(["scenario", "label"]).size().to_string())

# ==================================================
# SPLIT BY COLLECTION SESSION
# ==================================================

# Rows from one collection session must stay together.
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
)

train_idx, test_idx = next(
    splitter.split(
        df,
        groups=df["run_id"],
    )
)

train_df = df.iloc[train_idx].copy()
test_df = df.iloc[test_idx].copy()

train_sessions = set(train_df["run_id"])
test_sessions = set(test_df["run_id"])

if train_sessions.intersection(test_sessions):
    raise SystemExit(
        "Data leakage detected: a session appears in both splits."
    )

# Isolation Forest is fitted using normal traffic only.
normal_train = train_df[
    train_df["label"] == "normal"
].copy()

if len(normal_train) < 20:
    raise SystemExit(
        "Too few normal training observations. "
        "Review the session split and dataset."
    )

if set(test_df["label"]) != {"normal", "abnormal"}:
    raise SystemExit(
        "The held-out sessions must contain both normal "
        "and abnormal-labelled observations. Try another "
        "RANDOM_STATE or collect more balanced sessions."
    )

print("\nTraining sessions:", len(train_sessions))
print("Testing sessions:", len(test_sessions))
print("Normal training samples:", len(normal_train))
print("Held-out test samples:", len(test_df))

print("\nTest label counts:")
print(test_df["label"].value_counts().to_string())

# ==================================================
# TRAIN ISOLATION FOREST
# ==================================================

model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=RANDOM_STATE,
)

model.fit(normal_train[FEATURES])

# ==================================================
# EVALUATE ON HELD-OUT SESSIONS
# ==================================================

# Isolation Forest: 1 = normal, -1 = anomalous.
predictions = model.predict(test_df[FEATURES])

y_true = test_df["label"].map(
    {"normal": 1, "abnormal": -1}
).to_numpy()

print("\n" + "=" * 60)
print("HELD-OUT EVALUATION")
print("=" * 60)

print("\nConfusion matrix (rows=true, columns=predicted)")
print("Order: normal, abnormal")
cm = confusion_matrix(
    y_true,
    predictions,
    labels=[1, -1],
)
print(cm)

print("\nClassification report:")
print(
    classification_report(
        y_true,
        predictions,
        labels=[1, -1],
        target_names=["normal", "abnormal"],
        zero_division=0,
    )
)

print(
    "Accuracy:",
    round(accuracy_score(y_true, predictions), 4),
)

# Normal rows predicted abnormal are false positives.
normal_mask = y_true == 1
normal_count = int(normal_mask.sum())
false_positives = int(
    ((predictions == -1) & normal_mask).sum()
)

false_positive_rate = (
    false_positives / normal_count
    if normal_count else float("nan")
)

print(
    "False-positive rate:",
    round(false_positive_rate, 4),
)

# ==================================================
# SAVE MODEL SEPARATELY
# ==================================================

joblib.dump(
    {
        "model": model,
        "features": FEATURES,
        "dataset": DATASET.name,
        "training_method": "IsolationForest trained on normal traffic",
        "random_state": RANDOM_STATE,
        "training_sessions": sorted(train_sessions),
        "test_sessions": sorted(test_sessions),
    },
    MODEL_FILE,
)

print("\nNew model saved to:", MODEL_FILE)
print("Existing realtime_model.joblib was not overwritten.")
print("\nTraining and evaluation completed.")
