import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix


# ==========================================
# 1. Load dataset
# ==========================================

DATASET = "../results/results.csv"

df = pd.read_csv(DATASET)

print("Dataset loaded successfully.")
print("Total samples:", len(df))


# ==========================================
# 2. Select traffic features
# ==========================================

features = [
    "packets",
    "total_bytes",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "duration",
    "packets_per_second",
    "client_to_server",
    "server_to_client"
]

X = df[features]


# ==========================================
# 3. Select only NORMAL traffic for training
# ==========================================

normal_data = df[df["label"] == "normal"]

X_normal = normal_data[features]

print("\nNormal samples used for training:", len(X_normal))


# ==========================================
# 4. Create Isolation Forest
# ==========================================

model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42
)


# ==========================================
# 5. Train model
# ==========================================

model.fit(X_normal)

print("Isolation Forest training completed.")


# ==========================================
# 6. Predict all traffic
# ==========================================

predictions = model.predict(X)


# Isolation Forest:
#  1  = normal
# -1  = anomaly

df["prediction"] = predictions


# ==========================================
# 7. Convert prediction into labels
# ==========================================

df["predicted_label"] = df["prediction"].map({
    1: "normal",
    -1: "abnormal"
})


# ==========================================
# 8. Display results
# ==========================================

print("\n========== DETECTION RESULTS ==========")

print(
    df[
        [
            "session",
            "label",
            "predicted_label"
        ]
    ].to_string(index=False)
)


# ==========================================
# 9. Confusion matrix
# ==========================================

actual = df["label"]
predicted = df["predicted_label"]

cm = confusion_matrix(
    actual,
    predicted,
    labels=["normal", "abnormal"]
)

print("\n========== CONFUSION MATRIX ==========")

print("                 Predicted")
print("                 Normal  Abnormal")
print(
    f"Actual Normal    {cm[0][0]:6d}  {cm[0][1]:8d}"
)
print(
    f"Actual Abnormal  {cm[1][0]:6d}  {cm[1][1]:8d}"
)


# ==========================================
# 10. Classification report
# ==========================================

print("\n========== CLASSIFICATION REPORT ==========")

print(
    classification_report(
        actual,
        predicted,
        labels=["normal", "abnormal"],
        zero_division=0
    )
)


# ==========================================
# 11. Save results
# ==========================================

OUTPUT_FILE = "../results/detection_results.csv"

df.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\nDetection results saved to:")
print(OUTPUT_FILE)