
from scapy.all import sniff
from pathlib import Path
import joblib
import pandas as pd
import sys
import time
import traceback

# ==================================================
# CONFIGURATION
# ==================================================

SERVER_PORT = 8443
WINDOW_SECONDS = 5
INTERFACE = r"\Device\NPF_Loopback"

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_FILE = BASE_DIR / "results" / "realtime_model_v2.joblib"

# ==================================================
# IMPORT SHARED FEATURE EXTRACTOR
# ==================================================

SECURITY_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SECURITY_DIR))

from feature_extractor import extract_features, FEATURES

# ==================================================
# DASHBOARD EVENT BRIDGE
# ==================================================

try:
    from dashboard.event_bridge import emit_event
except ImportError:
    def emit_event(event_type, message, **details):
        pass


def report(event_type, message, **details):
    """Send dashboard events without stopping packet monitoring."""
    try:
        emit_event(event_type, message, **details)
    except Exception as exc:
        print(f"[Dashboard event warning] {exc}")


# ==================================================
# LOAD MODEL V2
# ==================================================

if not MODEL_FILE.exists():
    raise SystemExit(f"Model file not found: {MODEL_FILE}")

bundle = joblib.load(MODEL_FILE)

model = bundle["model"]
MODEL_FEATURES = bundle["features"]

if list(FEATURES) != list(MODEL_FEATURES):
    raise SystemExit(
        "Feature mismatch between the live extractor and trained model.\n"
        f"Extractor features: {FEATURES}\n"
        f"Model features: {MODEL_FEATURES}"
    )

# ==================================================
# STARTUP
# ==================================================

print("=" * 55)
print("REAL-TIME TLS TRAFFIC ANOMALY DETECTOR")
print("=" * 55)
print("Model:", MODEL_FILE.name)
print("Monitoring TCP port:", SERVER_PORT)
print("Interface:", INTERFACE)
print("Observation window:", WINDOW_SECONDS, "seconds")
print("Features:", len(FEATURES))
print("Press Ctrl+C to stop.")

report(
    "detector_started",
    "Real-time traffic anomaly detector started.",
    model=MODEL_FILE.name,
    server_port=SERVER_PORT,
    interface=INTERFACE,
    window_seconds=WINDOW_SECONDS,
    features=list(FEATURES),
)

# ==================================================
# HELPER: PREDICTION LABEL
# ==================================================

def get_prediction_label(prediction):
    """
    Preserve the existing model's label mapping.
    Model output 1 = NORMAL; output 0 = ANOMALOUS.
    """
    if prediction == 1:
        return "NORMAL"

    if prediction == 0:
        return "ANOMALOUS"

    return f"UNKNOWN ({prediction})"


# ==================================================
# CAPTURE, EXTRACT FEATURES, PREDICT AND REPORT
# ==================================================

window_id = 0

try:
    while True:
        capture_started = time.time()

        packets = sniff(
            iface=INTERFACE,
            filter=f"tcp port {SERVER_PORT}",
            timeout=WINDOW_SECONDS,
            store=True,
        )

        capture_duration = time.time() - capture_started
        window_id += 1

        features = extract_features(
            packets,
            window_seconds=WINDOW_SECONDS,
        )

        # -------------------------------------------------
        # No matching traffic in this window
        # -------------------------------------------------
        if features is None:
            message = f"Window {window_id}: No matching traffic."

            print("\n" + message)

            report(
                "traffic_window",
                message,
                window_id=window_id,
                packets=0,
                total_bytes=0,
                avg_packet_size=0,
                min_packet_size=0,
                max_packet_size=0,
                duration=0,
                packets_per_second=0,
                client_to_server=0,
                server_to_client=0,
                prediction="NO_TRAFFIC",
                capture_duration=round(capture_duration, 3),
            )

            continue

        # -------------------------------------------------
        # Build model input using the trained feature order
        # -------------------------------------------------
        row = pd.DataFrame(
            [[features[name] for name in MODEL_FEATURES]],
            columns=MODEL_FEATURES,
        )

        prediction = int(model.predict(row)[0])
        result = get_prediction_label(prediction)

        # Prepare serializable feature values.
        feature_details = {
            name: float(features[name])
            for name in FEATURES
        }

        # -------------------------------------------------
        # Print actual traffic measurements
        # -------------------------------------------------
        print("\n" + "=" * 55)
        print(f"WINDOW {window_id}")
        print("=" * 55)
        print("Packets:", features["packets"])
        print("Total bytes:", features["total_bytes"])
        print("Average packet size:", features["avg_packet_size"])
        print("Minimum packet size:", features["min_packet_size"])
        print("Maximum packet size:", features["max_packet_size"])
        print(
            "Observed packet span:",
            features["duration"],
            "seconds",
        )
        print(
            "Packet rate:",
            features["packets_per_second"],
            "packets/second",
        )
        print("Client to server:", features["client_to_server"])
        print("Server to client:", features["server_to_client"])
        print("Prediction:", result)

        # -------------------------------------------------
        # Send measured features to the dashboard
        # -------------------------------------------------
        report(
            "traffic_window",
            f"Traffic features collected for window {window_id}.",
            window_id=window_id,
            packets=float(features["packets"]),
            total_bytes=float(features["total_bytes"]),
            avg_packet_size=float(features["avg_packet_size"]),
            min_packet_size=float(features["min_packet_size"]),
            max_packet_size=float(features["max_packet_size"]),
            duration=float(features["duration"]),
            packets_per_second=float(
                features["packets_per_second"]
            ),
            client_to_server=float(
                features["client_to_server"]
            ),
            server_to_client=float(
                features["server_to_client"]
            ),
            capture_duration=round(capture_duration, 3),
        )

        # -------------------------------------------------
        # Send actual model prediction to the dashboard
        # -------------------------------------------------
        report(
            "traffic_prediction",
            f"Model v2 classified window {window_id}: {result}.",
            window_id=window_id,
            prediction=result,
            prediction_value=prediction,
            model=MODEL_FILE.name,
            features=feature_details,
        )

        if result == "ANOMALOUS":
            print("ALERT: Model classified this traffic window as anomalous.")

            report(
                "anomaly_alert",
                f"Model v2 flagged traffic window {window_id} as anomalous.",
                window_id=window_id,
                prediction=result,
                model=MODEL_FILE.name,
            )

except KeyboardInterrupt:
    print("\nMonitoring stopped by user.")

    report(
        "detector_stopped",
        "Real-time traffic anomaly detector stopped by user.",
        last_window_id=window_id,
    )

except Exception as exc:
    print("\nDetector error:", repr(exc))
    traceback.print_exc()

    report(
        "detector_error",
        "The real-time detector encountered an error.",
        error=repr(exc),
        last_window_id=window_id,
    )

    raise
