
from scapy.all import sniff, IP, TCP
from collections import Counter
import time

SERVER_PORT = 8443
WINDOW_SECONDS = 5

stats = {
    "packets": 0,
    "total_bytes": 0,
    "sizes": [],
    "client_to_server": 0,
    "server_to_client": 0,
}

def process_packet(packet):
    if IP not in packet or TCP not in packet:
        return

    tcp = packet[TCP]

    if tcp.sport != SERVER_PORT and tcp.dport != SERVER_PORT:
        return

    size = len(packet)

    stats["packets"] += 1
    stats["total_bytes"] += size
    stats["sizes"].append(size)

    if tcp.dport == SERVER_PORT:
        stats["client_to_server"] += 1
    else:
        stats["server_to_client"] += 1

def report_window():
    count = stats["packets"]

    if count == 0:
        print("No packets observed in this window.")
    else:
        sizes = stats["sizes"]

        print("\n--- LIVE TRAFFIC FEATURES ---")
        print("Packets:", count)
        print("Total bytes:", stats["total_bytes"])
        print("Average packet size:", round(stats["total_bytes"] / count, 2))
        print("Minimum packet size:", min(sizes))
        print("Maximum packet size:", max(sizes))
        print("Packets per second:", round(count / WINDOW_SECONDS, 2))
        print("Client to server:", stats["client_to_server"])
        print("Server to client:", stats["server_to_client"])

    for key in stats:
        if isinstance(stats[key], list):
            stats[key] = []
        else:
            stats[key] = 0

print("Real-time feature extraction started.")
print("Monitoring TCP port 8443 in five-second windows.")
print("Press Ctrl+C to stop.")

try:
    while True:
        start = time.monotonic()

        packets = sniff(
            iface=r"\Device\NPF_Loopback",
            filter="tcp port 8443",
            timeout=WINDOW_SECONDS,
            store=True
        )

        for packet in packets:
            process_packet(packet)

        report_window()

except KeyboardInterrupt:
    print("\nMonitoring stopped.")
