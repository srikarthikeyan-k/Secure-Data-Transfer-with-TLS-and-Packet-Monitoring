
import socket
import ssl
import sys
import time
from pathlib import Path

# =========================================================
# CONFIGURATION
# =========================================================

HOST = "127.0.0.1"
PORT = 8443
SERVER_HOSTNAME = "localhost"

BASE_DIR = Path(__file__).resolve().parent.parent
CA_FILE = BASE_DIR / "certificates" / "ca.crt"

TIMEOUT_SECONDS = 5
MAX_OPERATIONS = 100

# =========================================================
# DASHBOARD EVENT INTEGRATION
# =========================================================

# Ensure Python can find the dashboard package when this
# script is launched from the client subfolder.
sys.path.insert(0, str(BASE_DIR))

try:
    from dashboard.event_bridge import emit_event
except ImportError as exc:
    raise SystemExit(
        "Could not import dashboard.event_bridge.\n"
        f"Project directory: {BASE_DIR}\n"
        "Check that dashboard/event_bridge.py exists.\n"
        f"Import error: {exc}"
    )


def report(event_type, message, **details):
    """Write a backend event without interrupting TLS communication."""
    try:
        emit_event(event_type, message, **details)
    except Exception as exc:
        print(f"[Dashboard event warning] {exc}")


# =========================================================
# TLS CONFIGURATION
# =========================================================

if not CA_FILE.is_file():
    raise FileNotFoundError(f"CA certificate not found: {CA_FILE}")

context = ssl.create_default_context(
    ssl.Purpose.SERVER_AUTH,
    cafile=str(CA_FILE),
)

context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED

# =========================================================
# TLS SESSION KEY LOGGING FOR WIRESHARK
# =========================================================

KEYLOG_FILE = BASE_DIR / "results" / "tls_keys.log"
KEYLOG_FILE.parent.mkdir(parents=True, exist_ok=True)

context.keylog_filename = str(KEYLOG_FILE)

print("TLS session key log:", KEYLOG_FILE)


# =========================================================
# TLS CONNECTION
# =========================================================

def connect_to_server():
    """Establish TLS and validate the server certificate."""

    report(
        "tcp_connecting",
        "Client is connecting to the TLS server.",
        host=HOST,
        port=PORT,
    )

    raw_socket = None

    try:
        raw_socket = socket.create_connection(
            (HOST, PORT),
            timeout=TIMEOUT_SECONDS,
        )
        report(
    "tcp_connected",
    "TCP connection established. TLS negotiation is starting next.",
    local_address=str(raw_socket.getsockname()),
    peer_address=str(raw_socket.getpeername()),
)
        report(
            "tls_handshake_started",
            "TCP connected; TLS handshake is starting.",
            host=HOST,
            port=PORT,
        )

        tls_conn = context.wrap_socket(
            raw_socket,
            server_hostname=SERVER_HOSTNAME,
        )

        tls_conn.settimeout(TIMEOUT_SECONDS)

        # A successful wrap_socket call completes the handshake
        # and validates the certificate and hostname.
        report(
            "certificate_verified",
            "Server certificate and hostname validated successfully.",
            hostname=SERVER_HOSTNAME,
            tls_version=tls_conn.version(),
        )

        report(
            "tls_connected",
            "Secure TLS connection established.",
            tls_version=tls_conn.version(),
            cipher=str(tls_conn.cipher()),
        )

        print("TLS certificate validated")
        print("TLS version:", tls_conn.version())
        print("Cipher:", tls_conn.cipher())

        return tls_conn

    except ssl.SSLCertVerificationError as exc:
        report(
            "certificate_error",
            "Server certificate validation failed.",
            error=str(exc),
        )

        if raw_socket is not None:
            raw_socket.close()

        raise

    except (OSError, ssl.SSLError) as exc:
        report(
            "tls_error",
            "TLS connection failed.",
            error=str(exc),
        )

        if raw_socket is not None:
            raw_socket.close()

        raise


# =========================================================
# SEND AND RECEIVE HELPERS
# =========================================================

def send_message(tls_conn, message):
    """Send application data through the established TLS socket."""
    tls_conn.sendall(message)

    report(
        "message_sent",
        "Client sent application data through TLS.",
        message_length=len(message),
    )


def receive_response(tls_conn):
    """Receive one response using the existing server protocol."""
    return tls_conn.recv(4096)


def receive_and_report(tls_conn):
    response = receive_response(tls_conn)

    report(
        "response_received",
        (
            "Client received an application response."
            if response
            else "Server closed the connection without another response."
        ),
        response_length=len(response),
    )

    return response


# =========================================================
# MODE 1: SMALL MESSAGE
# =========================================================

def mode_1():
    print("\nNORMAL MODE 1: Small message")

    with connect_to_server() as tls_conn:
        send_message(tls_conn, b"Hello from secure TLS client")

        response = receive_and_report(tls_conn)
        print("Received:", response.decode(errors="replace"))


# =========================================================
# MODE 2: REPEATED TELEMETRY
# =========================================================

def mode_2():
    print("\nNORMAL MODE 2: Repeated telemetry")

    messages = [
        b"Temperature = 25 C",
        b"Humidity = 60 percent",
        b"Status = NORMAL",
    ]

    with connect_to_server() as tls_conn:
        for message in messages:
            send_message(tls_conn, message)

            response = receive_and_report(tls_conn)
            print("Received:", response.decode(errors="replace"))

            time.sleep(0.5)


# =========================================================
# MODE 3: LARGER LEGITIMATE MESSAGE
# =========================================================

def mode_3():
    print("\nNORMAL MODE 3: Larger legitimate message")

    message = (
        b"Normal sensor data: "
        b"Temperature=25C, "
        b"Humidity=60%, "
        b"Pressure=1013hPa, "
        b"Status=SAFE"
    )

    with connect_to_server() as tls_conn:
        send_message(tls_conn, message)

        response = receive_and_report(tls_conn)
        print("Received:", response.decode(errors="replace"))


# =========================================================
# MODE 4: LARGE PAYLOAD
# =========================================================

def mode_4(size_kb):
    print("\nNORMAL MODE 4: Legitimate large-payload test")

    size_bytes = size_kb * 1024
    print("Sending", size_bytes, "bytes")

    report(
        "test_started",
        "Large-payload test started.",
        test_mode=4,
        size_kb=size_kb,
        size_bytes=size_bytes,
    )

    with connect_to_server() as tls_conn:
        chunk_size = 4096
        remaining = size_bytes

        while remaining > 0:
            chunk_length = min(chunk_size, remaining)
            tls_conn.sendall(b"A" * chunk_length)
            remaining -= chunk_length

        report(
            "message_sent",
            "Large payload sent through TLS.",
            message_length=size_bytes,
        )

        # Preserve the existing server's half-close behavior.
        tls_conn.shutdown(socket.SHUT_WR)

        total_received = 0

        while True:
            data = tls_conn.recv(4096)

            if not data:
                break

            total_received += len(data)

        report(
            "response_received",
            "Large-payload response transfer completed.",
            response_length=total_received,
        )

        print("Received", total_received, "response bytes")
        print("Transfer completed")


# =========================================================
# MODE 5: CONTROLLED CONNECTION BURST
# =========================================================

def mode_5(count):
    print("\nABNORMAL TEST MODE 5: Rapid connection burst")
    print("Connections requested:", count)

    report(
        "test_started",
        "Controlled rapid-connection test started.",
        test_mode=5,
        requested_connections=count,
    )

    completed = 0

    for index in range(count):
        try:
            with connect_to_server() as tls_conn:
                send_message(tls_conn, b"Connection burst test")

                response = receive_and_report(tls_conn)

                if response:
                    completed += 1

            if (index + 1) % 10 == 0:
                print(
                    "Attempted:", index + 1,
                    "Completed:", completed,
                )

        except (OSError, ssl.SSLError) as exc:
            report(
                "client_error",
                "A connection-burst request failed.",
                connection_number=index + 1,
                error=str(exc),
            )
            print(f"Connection {index + 1} failed: {exc}")

    report(
        "test_completed",
        "Controlled connection-burst test completed.",
        test_mode=5,
        requested_connections=count,
        successful_connections=completed,
    )

    print("Successful request/response connections:", completed)
    print("This is a controlled test, not proof of malicious activity.")


# =========================================================
# MODE 6: RAPID MESSAGES OVER ONE TLS CONNECTION
# =========================================================

def mode_6(count):
    print("\nABNORMAL TEST MODE 6: Rapid message burst")
    print("Messages requested:", count)

    report(
        "test_started",
        "Controlled rapid-message test started.",
        test_mode=6,
        requested_messages=count,
    )

    completed = 0

    try:
        with connect_to_server() as tls_conn:
            for index in range(count):
                message = f"BURST_TEST_MESSAGE_{index + 1:03d}".encode()

                send_message(tls_conn, message)

                response = receive_and_report(tls_conn)

                if not response:
                    print("Server closed the connection early.")
                    break

                completed += 1

    except (OSError, ssl.SSLError) as exc:
        report(
            "client_error",
            "The rapid-message test failed.",
            error=str(exc),
        )
        print("Message burst failed:", exc)

    report(
        "test_completed",
        "Controlled rapid-message test completed.",
        test_mode=6,
        requested_messages=count,
        completed_messages=completed,
    )

    print("Completed message exchanges:", completed)
    print("This is a controlled test, not proof of malicious activity.")


# =========================================================
# ARGUMENT VALIDATION
# =========================================================

def parse_count(value):
    count = int(value)

    if not 1 <= count <= MAX_OPERATIONS:
        raise ValueError(
            f"Value must be between 1 and {MAX_OPERATIONS}."
        )

    return count


# =========================================================
# MAIN
# =========================================================

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("python client/client.py 1")
        print("python client/client.py 2")
        print("python client/client.py 3")
        print("python client/client.py 4 <size_in_KB>")
        print("python client/client.py 5 <connection_count>")
        print("python client/client.py 6 <message_count>")
        return

    mode = sys.argv[1]

    try:
        if mode == "1":
            mode_1()

        elif mode == "2":
            mode_2()

        elif mode == "3":
            mode_3()

        elif mode == "4":
            if len(sys.argv) != 3:
                raise ValueError(
                    "Usage: python client/client.py 4 <size_in_KB>"
                )
            mode_4(parse_count(sys.argv[2]))

        elif mode == "5":
            if len(sys.argv) != 3:
                raise ValueError(
                    "Usage: python client/client.py 5 <connection_count>"
                )
            mode_5(parse_count(sys.argv[2]))

        elif mode == "6":
            if len(sys.argv) != 3:
                raise ValueError(
                    "Usage: python client/client.py 6 <message_count>"
                )
            mode_6(parse_count(sys.argv[2]))

        else:
            raise ValueError("Mode must be 1, 2, 3, 4, 5, or 6.")

    except ssl.SSLCertVerificationError as exc:
        print("Certificate validation failed:", exc)

    except (ValueError, OSError, ssl.SSLError) as exc:
        print("Error:", exc)


if __name__ == "__main__":
    main()
