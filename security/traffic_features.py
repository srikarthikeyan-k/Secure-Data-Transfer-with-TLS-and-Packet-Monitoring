from scapy.all import rdpcap, TCP
import csv
import os

# Folders containing our PCAP files
NORMAL_FOLDER = "../captures/normal"
ABNORMAL_FOLDER = "../captures/abnormal"

# Output CSV file
RESULTS_FILE = "../results/results.csv"

# TLS server port
SERVER_PORT = 8443


def extract_features(pcap_file):

    packets = rdpcap(pcap_file)

    # Keep only TCP packets involving port 8443
    tls_packets = []

    for packet in packets:

        if TCP in packet:

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            if source_port == SERVER_PORT or destination_port == SERVER_PORT:
                tls_packets.append(packet)

    # No relevant traffic found
    if len(tls_packets) == 0:
        return None

    # -----------------------------
    # Packet count
    # -----------------------------

    total_packets = len(tls_packets)

    # -----------------------------
    # Packet sizes
    # -----------------------------

    packet_sizes = [len(packet) for packet in tls_packets]

    total_bytes = sum(packet_sizes)

    average_packet_size = total_bytes / total_packets

    minimum_packet_size = min(packet_sizes)

    maximum_packet_size = max(packet_sizes)

    # -----------------------------
    # Duration
    # -----------------------------

    start_time = tls_packets[0].time
    end_time = tls_packets[-1].time

    duration = float(end_time - start_time)

    if duration > 0:
        packets_per_second = total_packets / duration
    else:
        packets_per_second = 0

    # -----------------------------
    # Traffic direction
    # -----------------------------

    client_to_server = 0
    server_to_client = 0

    for packet in tls_packets:

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        if destination_port == SERVER_PORT:
            client_to_server += 1

        elif source_port == SERVER_PORT:
            server_to_client += 1

    return [
        total_packets,
        total_bytes,
        round(average_packet_size, 2),
        minimum_packet_size,
        maximum_packet_size,
        round(duration, 4),
        round(packets_per_second, 2),
        client_to_server,
        server_to_client
    ]


# ----------------------------------------
# Create results folder
# ----------------------------------------

os.makedirs("../results", exist_ok=True)


# ----------------------------------------
# Create new CSV
# ----------------------------------------

with open(RESULTS_FILE, "w", newline="") as file:

    writer = csv.writer(file)

    # CSV header
    writer.writerow([
        "session",
        "packets",
        "total_bytes",
        "avg_packet_size",
        "min_packet_size",
        "max_packet_size",
        "duration",
        "packets_per_second",
        "client_to_server",
        "server_to_client",
        "label"
    ])


    # ====================================
    # PROCESS NORMAL TRAFFIC
    # ====================================

    normal_files = sorted(
        file for file in os.listdir(NORMAL_FOLDER)
        if file.endswith(".pcapng")
    )

    for index, pcap_file in enumerate(normal_files, start=1):

        pcap_path = os.path.join(
            NORMAL_FOLDER,
            pcap_file
        )

        features = extract_features(pcap_path)

        if features is not None:

            writer.writerow([
                f"normal_{index:02d}",
                *features,
                "normal"
            ])

            print(f"Processed normal: {pcap_file}")


    # ====================================
    # PROCESS ABNORMAL TRAFFIC
    # ====================================

    abnormal_files = sorted(
        file for file in os.listdir(ABNORMAL_FOLDER)
        if file.endswith(".pcapng")
    )

    for index, pcap_file in enumerate(abnormal_files, start=1):

        pcap_path = os.path.join(
            ABNORMAL_FOLDER,
            pcap_file
        )

        features = extract_features(pcap_path)

        if features is not None:

            writer.writerow([
                f"abnormal_{index:02d}",
                *features,
                "abnormal"
            ])

            print(f"Processed abnormal: {pcap_file}")


print("\nTraffic dataset created successfully.")
print("Saved to:", RESULTS_FILE)