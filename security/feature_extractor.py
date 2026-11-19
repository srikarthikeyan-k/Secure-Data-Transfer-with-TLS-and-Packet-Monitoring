
from scapy.all import IP, TCP

SERVER_PORT = 8443

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


def extract_features(packets, window_seconds=5):
    """
    Extract traffic features from one fixed observation window.

    Use the same observation-window duration and feature definitions
    for dataset collection, model evaluation, and live detection.
    """

    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero.")

    packets = [
        packet for packet in packets
        if IP in packet
        and TCP in packet
        and (
            packet[TCP].sport == SERVER_PORT
            or packet[TCP].dport == SERVER_PORT
        )
    ]

    if not packets:
        return None

    sizes = [len(packet) for packet in packets]
    total_packets = len(packets)
    total_bytes = sum(sizes)

    timestamps = [float(packet.time) for packet in packets]
    packet_duration = max(timestamps) - min(timestamps)

    client_to_server = sum(
        1 for packet in packets
        if packet[TCP].dport == SERVER_PORT
    )

    server_to_client = sum(
        1 for packet in packets
        if packet[TCP].sport == SERVER_PORT
    )

    return {
        "packets": total_packets,
        "total_bytes": total_bytes,
        "avg_packet_size": round(
            total_bytes / total_packets, 2
        ),
        "min_packet_size": min(sizes),
        "max_packet_size": max(sizes),
        "duration": round(packet_duration, 6),
        "packets_per_second": round(
            total_packets / window_seconds, 2
        ),
        "client_to_server": client_to_server,
        "server_to_client": server_to_client,
    }
