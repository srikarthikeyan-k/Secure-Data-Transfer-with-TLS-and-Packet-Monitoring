
from scapy.all import sniff
from pathlib import Path
import csv

from feature_extractor import extract_features, FEATURES

SERVER_PORT = 8443
WINDOW_SECONDS = 5
INTERFACE = r"\Device\NPF_Loopback"

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_FILE = BASE_DIR / "results" / "unseen_test_dataset.csv"

CSV_COLUMNS = FEATURES + ["label"]
VALID_LABELS = {"normal", "abnormal"}

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

if not OUTPUT_FILE.exists() or OUTPUT_FILE.stat().st_size == 0:
    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(CSV_COLUMNS)

print("UNSEEN TEST DATASET COLLECTOR")
print(f"Output: {OUTPUT_FILE}")
print("Capture window:", WINDOW_SECONDS, "seconds")
print("Use separate test runs from your training data.")
print("Labels: normal / abnormal")
print("Press Ctrl+C to stop.")

try:
    while True:
        input(
            "\nPrepare a client test in another terminal, "
            "then press Enter to capture a window..."
        )

        packets = sniff(
            iface=INTERFACE,
            filter=f"tcp port {SERVER_PORT}",
            timeout=WINDOW_SECONDS,
            store=True,
        )

        row = extract_features(packets, WINDOW_SECONDS)

        if row is None:
            print("No matching traffic. Try again.")
            continue

        print("\nCaptured features:")
        for feature in FEATURES:
            print(f"{feature}: {row[feature]}")

        label = input(
            "Known test label [normal/abnormal]: "
        ).strip().lower()

        if label not in VALID_LABELS:
            print("Invalid label. Sample not saved.")
            continue

        row["label"] = label

        with OUTPUT_FILE.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writerow(row)

        print("Saved test sample.")

except KeyboardInterrupt:
    print("\nTest dataset collection stopped.")
