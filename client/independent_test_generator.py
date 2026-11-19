
import socket
import ssl
import time

HOST = "127.0.0.1"
PORT = 8443
SERVER_NAME = "localhost"

MESSAGE_COUNT = 10
INTERVAL_SECONDS = 2

context = ssl.create_default_context(
    cafile=r"D:\TLS_Security_Project\certificates\ca.crt"
)

print("Independent Test A: Periodic Telemetry")
print(f"Messages: {MESSAGE_COUNT}")
print(f"Interval: {INTERVAL_SECONDS} seconds")

try:
    with socket.create_connection((HOST, PORT)) as raw_socket:
        with context.wrap_socket(
            raw_socket,
            server_hostname=SERVER_NAME
        ) as tls_socket:

            print("TLS connection established.")

            for index in range(MESSAGE_COUNT):
                message = (
                    f"telemetry_id={index + 1},"
                    f"temperature={24 + index * 0.2:.1f},"
                    f"humidity={50 + index}"
                ).encode()

                tls_socket.sendall(message)
                print(
                    f"Sent message {index + 1}/{MESSAGE_COUNT}: "
                    f"{len(message)} bytes"
                )

                response = tls_socket.recv(4096)
                print("Server response:", response.decode(errors="replace"))

                if index < MESSAGE_COUNT - 1:
                    time.sleep(INTERVAL_SECONDS)

    print("\nTest A completed.")

except (OSError, ssl.SSLError) as error:
    print("Test failed:", error)
    print("Check that the TLS server is running on port 8443.")
