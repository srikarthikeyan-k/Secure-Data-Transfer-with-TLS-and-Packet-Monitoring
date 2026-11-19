
import csv
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

from scapy.all import AsyncSniffer
from feature_extractor import extract_features, FEATURES

# ==================================================
# CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent.parent
CLIENT_FILE = BASE_DIR / "client" / "client.py"
OUTPUT_FILE = BASE_DIR / "results" / "realtime_dataset_v4.csv"

SERVER_PORT = 8443
INTERFACE = r"\Device\NPF_Loopback"

WINDOW_SECONDS = 5
SAMPLES_PER_SCENARIO = 100      # Pilot: 5 x 6 = 30
MAX_ATTEMPTS_PER_SCENARIO = 3  # Retry failed trials
CLIENT_TIMEOUT_SECONDS = 4.5   # Must fit within capture window

SCENARIOS = [
    {
        "name": "mode_1_small_message",
        "label": "normal",
        "args": ["1"],
    },
    {
        "name": "mode_2_repeated_telemetry",
        "label": "normal",
        "args": ["2"],
    },
    {
        "name": "mode_3_large_legitimate_message",
        "label": "normal",
        "args": ["3"],
    },
    {
        "name": "mode_4_large_payload_stress_test",
        "label": "normal",
        "args": ["4", "50"],
    },
    {
        "name": "high_rate_connection_test",
        "label": "abnormal",
        "args": ["5", "20"],
    },
    {
        "name": "rapid_message_burst_test",
        "label": "abnormal",
        "args": ["6", "20"],
    },
]

CSV_COLUMNS = [
    "timestamp",
    "run_id",
    "trial_id",
    "scenario",
    "label",
] + FEATURES


# ==================================================
# CSV SETUP AND RESUME SUPPORT
# ==================================================

def prepare_csv():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    if not OUTPUT_FILE.exists() or OUTPUT_FILE.stat().st_size == 0:
        with OUTPUT_FILE.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            csv.DictWriter(
                file, fieldnames=CSV_COLUMNS
            ).writeheader()
        return

    with OUTPUT_FILE.open(
        "r", newline="", encoding="utf-8"
    ) as file:
        header = next(csv.reader(file), [])

    if header != CSV_COLUMNS:
        raise SystemExit(
            f"CSV header mismatch: {OUTPUT_FILE}\n"
            "Existing data was preserved. Back up the file and "
            "use a new output filename for a different schema."
        )


def load_valid_counts():
    """Count existing rows for each expected scenario and label."""
    counts = {item["name"]: 0 for item in SCENARIOS}

    with OUTPUT_FILE.open(
        "r", newline="", encoding="utf-8"
    ) as file:
        for row in csv.DictReader(file):
            name = row.get("scenario")
            expected = next(
                (s for s in SCENARIOS if s["name"] == name),
                None,
            )

            if expected is None:
                continue

            if row.get("label") != expected["label"]:
                continue

            try:
                packets = int(row["packets"])
                total_bytes = int(row["total_bytes"])
            except (ValueError, KeyError, TypeError):
                continue

            if packets > 0 and total_bytes > 0:
                counts[name] += 1

    return counts


# ==================================================
# ONE FIXED-WINDOW TRIAL
# ==================================================

def capture_trial(run_id, scenario, attempt_number):
    trial_id = (
        f"{run_id}_{scenario['name']}_"
        f"{uuid.uuid4().hex[:8]}"
    )

    sniffer = AsyncSniffer(
        iface=INTERFACE,
        filter=f"tcp port {SERVER_PORT}",
        store=True,
    )

    client = None
    capture_started = False
    client_finished = False
    client_ok = False
    client_output = ""

    try:
        print(f"\nStarting trial: {trial_id}")

        # Start capture before launching the client.
        sniffer.start()
        capture_started = True
        time.sleep(0.2)

        start_time = time.monotonic()

        command = [
            sys.executable,
            str(CLIENT_FILE),
            *scenario["args"],
        ]

        client = subprocess.Popen(
            command,
            cwd=str(BASE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        try:
            output, _ = client.communicate(
                timeout=CLIENT_TIMEOUT_SECONDS
            )
            client_output = output or ""
            client_finished = True
            client_ok = client.returncode == 0

        except subprocess.TimeoutExpired:
            client.kill()
            output, _ = client.communicate()
            client_output = output or ""
            print("Client exceeded the time limit; trial rejected.")

        # Maintain the fixed observation-window duration.
        elapsed = time.monotonic() - start_time
        remaining = WINDOW_SECONDS - elapsed

        if remaining > 0:
            time.sleep(remaining)

    except Exception as exc:
        print("Trial error:", repr(exc))

    finally:
        if client is not None and client.poll() is None:
            client.kill()
            client.communicate()

        if capture_started:
            try:
                sniffer.stop()
            except Exception as exc:
                print("Capture stop error:", repr(exc))

    if not client_finished or not client_ok:
        print("Trial rejected: client did not finish successfully.")
        if client_output:
            print(client_output[-1000:])
        return False

    packets = sniffer.results

    if not packets:
        print("Trial rejected: no packets captured.")
        return False

    # Always use the same 5-second denominator as live detection.
    features = extract_features(
        packets,
        window_seconds=WINDOW_SECONDS,
    )

    if features is None or features["packets"] <= 0:
        print("Trial rejected: feature extraction failed.")
        return False

    # Require traffic in both directions for this request/response test.
    if (
        features["client_to_server"] <= 0
        or features["server_to_client"] <= 0
    ):
        print("Trial rejected: incomplete request/response capture.")
        return False

    row = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "run_id": run_id,
        "trial_id": trial_id,
        "scenario": scenario["name"],
        "label": scenario["label"],
        **features,
    }

    with OUTPUT_FILE.open(
        "a", newline="", encoding="utf-8"
    ) as file:
        csv.DictWriter(
            file, fieldnames=CSV_COLUMNS
        ).writerow(row)

    print(
        f"Saved: {scenario['name']} | "
        f"label={scenario['label']} | "
        f"packets={features['packets']} | "
        f"bytes={features['total_bytes']} | "
        f"rate={features['packets_per_second']}"
    )

    return True


# ==================================================
# MAIN AUTOMATION
# ==================================================

def main():
    if not CLIENT_FILE.exists():
        raise SystemExit(f"Client file not found: {CLIENT_FILE}")

    prepare_csv()
    counts = load_valid_counts()

    run_id = (
        datetime.now().strftime("%Y%m%d_%H%M%S")
        + "_"
        + uuid.uuid4().hex[:6]
    )

    print("=" * 60)
    print("AUTOMATED TLS DATASET COLLECTOR")
    print("=" * 60)
    print("Output:", OUTPUT_FILE)
    print("Capture window:", WINDOW_SECONDS, "seconds")
    print("Target per scenario:", SAMPLES_PER_SCENARIO)
    print("\nEnsure the TLS server is already running.")

    total_saved = 0

    try:
        for scenario in SCENARIOS:
            name = scenario["name"]
            saved = counts[name]

            print("\n" + "-" * 60)
            print("Scenario:", name)
            print("Expected label:", scenario["label"])
            print(f"Existing valid rows: {saved}")

            attempts_this_run = 0

            while saved < SAMPLES_PER_SCENARIO:
                if attempts_this_run >= MAX_ATTEMPTS_PER_SCENARIO:
                    print(
                        "Retry limit reached for this scenario. "
                        "Check server, certificates, and capture permissions."
                    )
                    break

                attempts_this_run += 1
                print(
                    f"Attempt {attempts_this_run}/"
                    f"{MAX_ATTEMPTS_PER_SCENARIO}; "
                    f"target progress {saved}/"
                    f"{SAMPLES_PER_SCENARIO}"
                )

                success = capture_trial(
                    run_id,
                    scenario,
                    attempts_this_run,
                )

                if success:
                    saved += 1
                    counts[name] += 1
                    total_saved += 1

            print(f"Current count for {name}: {counts[name]}")

    except KeyboardInterrupt:
        print("\nCollection interrupted by user.")

    finally:
        print("\n" + "=" * 60)
        print("COLLECTION SUMMARY")
        print("New rows saved this run:", total_saved)
        print("\nScenario counts:")

        for scenario in SCENARIOS:
            name = scenario["name"]
            print(
                f"{name}: {counts[name]}/"
                f"{SAMPLES_PER_SCENARIO}"
            )

        print("\nCSV:", OUTPUT_FILE)
        print("=" * 60)


if __name__ == "__main__":
    main()
