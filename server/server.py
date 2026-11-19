import json
import os
import re
import socket
import ssl
import struct
import threading
import uuid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CERT_FILE = BASE_DIR / "certificates" / "server.crt"
KEY_FILE = BASE_DIR / "certificates" / "server.key"
RULES_FILE = BASE_DIR / "results" / "response_rules.json"
STORAGE_AUDIO = BASE_DIR / "storage" / "audio"
STORAGE_VIDEO = BASE_DIR / "storage" / "video"

HOST = "127.0.0.1"
PORT = 8443
MAX_MEDIA_BYTES = 100 * 1024 * 1024

DEFAULT_REPLY = (
    "I received your question, but no custom reply has been configured "
    "for it yet."
)

MEDIA_MAGIC = b"\x00MD1"
TEXT_MAGIC = b"\x00TX1"
RECEIVE_MAGIC = b"\x00RC1"


def load_reply_rules():
    try:
        parsed = json.loads(RULES_FILE.read_text(encoding="utf-8"))
        if isinstance(parsed, dict):
            return {
                str(key).strip().casefold(): str(value)
                for key, value in parsed.items()
            }
    except (OSError, json.JSONDecodeError):
        pass

    return {}


def recv_exact(sock, size):
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(min(64 * 1024, size - len(data)))

        if not chunk:
            raise ConnectionError(
                f"Connection ended early: received {len(data)} "
                f"of {size} bytes."
            )

        data.extend(chunk)

    return bytes(data)


def send_json_line(sock, payload):
    message = json.dumps(
        payload,
        ensure_ascii=False
    ).encode("utf-8")

    sock.sendall(message + b"\n")


def receive_media(sock):
    header_len = struct.unpack("!I", recv_exact(sock, 4))[0]

    if not 1 <= header_len <= 4096:
        raise ValueError("Invalid media metadata header length.")

    metadata = json.loads(
        recv_exact(sock, header_len).decode("utf-8")
    )

    kind = metadata.get("type")
    filename = metadata.get("filename")
    size = metadata.get("size")

    if kind not in ("audio", "video"):
        raise ValueError("Unsupported media type.")

    if (
        not isinstance(filename, str)
        or Path(filename).name != filename
        or not re.fullmatch(
            r"[A-Za-z0-9 _().-]{1,180}\.(wav|mp4)",
            filename,
            re.I
        )
    ):
        raise ValueError("Unsafe or unsupported filename.")

    expected_ext = ".wav" if kind == "audio" else ".mp4"

    if Path(filename).suffix.lower() != expected_ext:
        raise ValueError("File extension does not match media type.")

    if (
        not isinstance(size, int)
        or size <= 0
        or size > MAX_MEDIA_BYTES
    ):
        raise ValueError("Media size is outside the permitted range.")

    destination_dir = (
        STORAGE_AUDIO if kind == "audio" else STORAGE_VIDEO
    )

    destination_dir.mkdir(parents=True, exist_ok=True)

    unique_name = f"{uuid.uuid4().hex}_{filename}"
    final_path = destination_dir / unique_name
    temp_path = destination_dir / f".{unique_name}.part"

    received = 0

    try:
        with temp_path.open("xb") as output:
            first = bytearray()

            while received < size:
                chunk = sock.recv(
                    min(64 * 1024, size - received)
                )

                if not chunk:
                    raise ConnectionError(
                        f"Media transfer interrupted at "
                        f"{received}/{size} bytes."
                    )

                if len(first) < 12:
                    first.extend(chunk[:12 - len(first)])

                output.write(chunk)
                received += len(chunk)

            output.flush()
            os.fsync(output.fileno())

        file_start = bytes(first)

        if kind == "audio":
            if not (
                file_start.startswith(b"RIFF")
                and file_start[8:12] == b"WAVE"
            ):
                raise ValueError(
                    "Received file does not contain a WAV RIFF/WAVE header."
                )

        if kind == "video":
            if len(file_start) < 8 or file_start[4:8] != b"ftyp":
                raise ValueError(
                    "Received file does not contain an MP4 ftyp header."
                )

        temp_path.replace(final_path)

    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass

        raise

    print(
        f"[MEDIA SAVED - AWAITING RECEIVE] "
        f"type={kind} file={final_path.name} bytes={received}",
        flush=True
    )

    return {
        "ok": True,
        "type": kind,
        "saved_as": unique_name,
        "bytes": received
    }


def handle_client(raw_conn, address, context):
    tls_sock = None
    pending_response = None

    try:
        raw_conn.settimeout(300)

        tls_sock = context.wrap_socket(
            raw_conn,
            server_side=True
        )

        print(
            f"[TLS CONNECTED] {address} | "
            f"TLS {tls_sock.version()} | "
            f"cipher={tls_sock.cipher()[0]}",
            flush=True
        )

        while True:
            tls_sock.settimeout(300)

            first = tls_sock.recv(1)

            if not first:
                break

            if first == b"\x00":
                magic = first + recv_exact(tls_sock, 3)

                # Receive audio/video data.
                if magic == MEDIA_MAGIC:
                    if pending_response is not None:
                        send_json_line(
                            tls_sock,
                            {
                                "ok": False,
                                "error": (
                                    "Receive the previous operation "
                                    "before sending another."
                                )
                            }
                        )
                        break

                    try:
                        pending_response = receive_media(tls_sock)

                    except Exception as exc:
                        print(
                            f"[MEDIA ERROR] {address}: {exc}",
                            flush=True
                        )

                        send_json_line(
                            tls_sock,
                            {
                                "ok": False,
                                "error": str(exc)
                            }
                        )
                        break

                    continue

                # Receive text request.
                if magic == TEXT_MAGIC:
                    if pending_response is not None:
                        send_json_line(
                            tls_sock,
                            {
                                "ok": False,
                                "error": (
                                    "Receive the previous operation "
                                    "before sending another."
                                )
                            }
                        )
                        break

                    header_len = struct.unpack(
                        "!I",
                        recv_exact(tls_sock, 4)
                    )[0]

                    if not 1 <= header_len <= 4096:
                        raise ValueError(
                            "Invalid text metadata header length."
                        )

                    metadata = json.loads(
                        recv_exact(
                            tls_sock,
                            header_len
                        ).decode("utf-8")
                    )

                    if (
                        metadata.get("type") != "text"
                        or not isinstance(
                            metadata.get("message"),
                            str
                        )
                    ):
                        raise ValueError(
                            "Invalid text operation frame."
                        )

                    question = metadata["message"].strip()

                    if (
                        not question
                        or len(question) > 4000
                        or "\n" in question
                        or "\r" in question
                    ):
                        raise ValueError(
                            "Text message is empty, too long, "
                            "or contains a line break."
                        )

                    print(
                        f"[CLIENT TEXT SENT - AWAITING RECEIVE] "
                        f"{question}",
                        flush=True
                    )

                    rules = load_reply_rules()

                    reply = rules.get(
                        question.casefold(),
                        DEFAULT_REPLY
                    )

                    pending_response = {
                        "ok": True,
                        "type": "text",
                        "response": reply
                    }

                    continue

                # Release the pending result only when requested.
                if magic == RECEIVE_MAGIC:
                    if pending_response is None:
                        send_json_line(
                            tls_sock,
                            {
                                "ok": False,
                                "error": (
                                    "No pending operation is "
                                    "available to receive."
                                )
                            }
                        )

                    else:
                        send_json_line(
                            tls_sock,
                            pending_response
                        )

                        print(
                            f"[SERVER RESULT RELEASED] "
                            f"type={pending_response.get('type')}",
                            flush=True
                        )

                        pending_response = None

                    continue

                raise ValueError(
                    f"Unknown application frame magic: {magic!r}"
                )

            # Backward-compatible legacy text protocol.
            data = bytearray(first)

            while data[-1:] != b"\n" and len(data) < 65536:
                part = tls_sock.recv(1)

                if not part:
                    break

                data.extend(part)

            question = bytes(data).decode(
                "utf-8",
                errors="replace"
            ).strip()

            if not question:
                continue

            print(
                f"[LEGACY CLIENT QUESTION] {question}",
                flush=True
            )

            rules = load_reply_rules()

            reply = rules.get(
                question.casefold(),
                DEFAULT_REPLY
            )

            tls_sock.sendall(
                (reply + "\n").encode("utf-8")
            )

            print(
                f"[LEGACY SERVER REPLY] {reply}",
                flush=True
            )

    except (
        ssl.SSLError,
        OSError,
        socket.timeout,
        ValueError,
        json.JSONDecodeError
    ) as exc:

        print(
            f"[CLIENT ERROR] {address}: {exc}",
            flush=True
        )

    finally:
        if tls_sock is not None:
            try:
                raw = tls_sock.unwrap()
                raw.close()

            except (
                ssl.SSLError,
                OSError,
                socket.timeout
            ):
                try:
                    tls_sock.close()
                except OSError:
                    pass

        else:
            try:
                raw_conn.close()
            except OSError:
                pass

        print(
            f"[DISCONNECTED] {address}",
            flush=True
        )


def main():
    if not CERT_FILE.is_file() or not KEY_FILE.is_file():
        raise FileNotFoundError(
            f"Server certificate/key not found. "
            f"Expected: {CERT_FILE} and {KEY_FILE}"
        )

    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    context.load_cert_chain(
        certfile=str(CERT_FILE),
        keyfile=str(KEY_FILE)
    )

    STORAGE_AUDIO.mkdir(
        parents=True,
        exist_ok=True
    )

    STORAGE_VIDEO.mkdir(
        parents=True,
        exist_ok=True
    )

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as server_sock:

        server_sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server_sock.bind((HOST, PORT))
        server_sock.listen(10)

        print(
            f"TLS server listening on {HOST}:{PORT}",
            flush=True
        )

        print(
            f"Audio storage: {STORAGE_AUDIO}",
            flush=True
        )

        print(
            f"Video storage: {STORAGE_VIDEO}",
            flush=True
        )

        print(
            f"Loading custom replies from {RULES_FILE}",
            flush=True
        )

        print(
            "Dashboard protocol: explicit Send/Receive framing enabled",
            flush=True
        )

        while True:
            conn, address = server_sock.accept()

            threading.Thread(
                target=handle_client,
                args=(conn, address, context),
                daemon=True
            ).start()


if __name__ == "__main__":
    main()