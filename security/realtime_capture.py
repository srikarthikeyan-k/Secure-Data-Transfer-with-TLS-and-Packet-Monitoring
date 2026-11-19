
from scapy.all import sniff, IP, TCP

SERVER_PORT = 8443
LOOPBACK_INTERFACE = r"\Device\NPF_Loopback"

def show_packet(packet):
    if IP in packet and TCP in packet:
        tcp = packet[TCP]

        if tcp.sport == SERVER_PORT or tcp.dport == SERVER_PORT:
            direction = (
                "CLIENT -> SERVER"
                if tcp.dport == SERVER_PORT
                else "SERVER -> CLIENT"
            )

            print(
                f"{direction} | "
                f"Size: {len(packet)} bytes | "
                f"Source: {packet[IP].src}:{tcp.sport} | "
                f"Destination: {packet[IP].dst}:{tcp.dport} | "
                f"Flags: {tcp.flags}",
                flush=True
            )

print("Starting live TLS traffic capture...")
print("Interface: Software Loopback Interface")
print("Monitoring TCP port 8443. Press Ctrl+C to stop.")

sniff(
    iface=LOOPBACK_INTERFACE,
    filter="tcp port 8443",
    prn=show_packet,
    store=False
)
