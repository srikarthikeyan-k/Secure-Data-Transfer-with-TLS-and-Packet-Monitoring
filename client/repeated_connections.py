
import socket
import ssl
import time

HOST = "127.0.0.1"
PORT = 8443
SERVER_NAME = "localhost"
CA_FILE = "../certificates/ca.crt"

NUMBER_OF_CONNECTIONS = 30
DELAY_SECONDS = 0.1

context = ssl.create_default_context(cafile=CA_FILE)

success = 0
failures = 0

print("Starting controlled repeated-connection test...")

for i in range(NUMBER_OF_CONNECTIONS):
    try:
        with socket.create_connection((HOST, PORT), timeout=3) as sock:
            with context.wrap_socket(
                sock, server_hostname=SERVER_NAME
            ) as tls_sock:
                tls_sock.sendall(b"Test telemetry message")
                tls_sock.recv(1024)
                success += 1

        print(f"Connection {i + 1}: TLS successful")

    except (OSError, ssl.SSLError) as error:
        failures += 1
        print(f"Connection {i + 1}: failed - {error}")

    time.sleep(DELAY_SECONDS)

print("\nTest completed.")
print("Successful connections:", success)
print("Failed connections:", failures)
