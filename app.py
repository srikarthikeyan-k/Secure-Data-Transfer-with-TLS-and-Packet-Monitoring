import html
import json
import socket
import ssl
import subprocess
import struct
import time
import wave
from pathlib import Path

import streamlit as st
from streamlit_autorefresh import st_autorefresh

BASE_DIR = Path(__file__).resolve().parent
CA_FILE = BASE_DIR / "certificates" / "ca.crt"
RESULTS_DIR = BASE_DIR / "results"
RULES_FILE = RESULTS_DIR / "response_rules.json"
AUDIO_DIR = BASE_DIR / "media" / "audio"
VIDEO_DIR = BASE_DIR / "media" / "video"
STORAGE_AUDIO_DIR = BASE_DIR / "storage" / "audio"
STORAGE_VIDEO_DIR = BASE_DIR / "storage" / "video"

MAX_MEDIA_BYTES = 100 * 1024 * 1024
MEDIA_MAGIC = b"\x00MD1"
TEXT_MAGIC = b"\x00TX1"
RECEIVE_MAGIC = b"\x00RC1"

HOST = "127.0.0.1"
PORT = 8443
SERVER_HOSTNAME = "localhost"
TSHARK_DEFAULT = r"C:\Program Files\Wireshark\tshark.exe"

STAGES = [
    ("tcp", "TCP connect"),
    ("tls", "TLS handshake"),
    ("send", "Send request"),
    ("receive", "Receive response"),
    ("close", "Close connection"),
]
STAGE_LABELS = {key: label for key, label in STAGES}

st.set_page_config(
    page_title="TLS Communication Visualizer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st_autorefresh(interval=1000, key="tls_visualizer_refresh")

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(
            145deg,
            #07111f 0%,
            #0b1728 60%,
            #101d32 100%
        );
        color: #edf4ff;
    }

    h1,h2,h3,p,label {
        color: #edf4ff;
    }

    .hero {
        padding: 20px 24px;
        border-radius: 16px;
        border: 1px solid #263c59;
        background: linear-gradient(110deg,#12243b,#102d3c);
        margin-bottom: 16px;
    }

    .hero-title {
        font-size: 30px;
        font-weight: 800;
    }

    .hero-sub {
        color: #a9c0dc;
        margin-top: 6px;
        font-size: 14px;
    }

    .device {
        background: linear-gradient(160deg,#142941,#0d1c30);
        border: 1px solid #34516e;
        border-radius: 18px;
        padding: 18px 10px;
        min-height: 145px;
        text-align: center;
    }

    .server {
        border-color: #267f70;
        background: linear-gradient(160deg,#103b3a,#102b35);
    }

    .device-icon {
        font-size: 42px;
    }

    .device-name {
        font-size: 20px;
        font-weight: 800;
    }

    .device-sub {
        color: #b4c8df;
        font-size: 12px;
        margin-top: 4px;
    }

    .muted {
        color: #9eb2cb;
        font-size: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <div class="hero-title">
        🔐 TLS Communication Visualizer
      </div>
      <div class="hero-sub">
        Real TCP connection · certificate-validated TLS ·
        one-at-a-time text/audio/video transfer · explicit Receive ·
        live TLS ciphertext and packet metrics
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)


DEFAULTS = {
    "stage": 0,
    "tls_sock": None,
    "request": "What is your name?",
    "server_reply": "My name is machine1.",
    "response": "",
    "last_error": "",
    "tcp_local": "",
    "tcp_peer": "",
    "client_port": "",
    "connection_stream_id": None,
    "connection_started_epoch": None,
    "connection_ended_epoch": None,
    "tls_version": "",
    "cipher": "",
    "sent_at": None,
    "received_at": None,
    "closed": False,
    "capture_proc": None,
    "pcap_proc": None,
    "capture_file": None,
    "pcap_file": None,
    "pcap_err_handle": None,
    "pcap_err_file": None,
    "capture_out_handle": None,
    "capture_err_handle": None,
    "capture_err_file": None,
    "capture_status": "Not started",
    "stage_windows": {},
    "packet_view": "tcp",
    "packet_view_widget": "tcp",
    "pending_operation": None,
    "last_transfer": {},
    "received_media": [],
    "certificate_preflight": None,
    "certificate_test_results": [],
}

for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


def _list_media_files(folder: Path, suffix: str):
    folder.mkdir(parents=True, exist_ok=True)

    return sorted(
        p for p in folder.iterdir()
        if p.is_file() and p.suffix.lower() == suffix
    )


def _recv_line_tls(sock, limit=65536):
    """Read one newline-delimited server acknowledgement."""

    data = bytearray()

    while len(data) < limit:
        part = sock.recv(1)

        if not part:
            break

        if part == b"\n":
            return bytes(data).rstrip(b"\r")

        data.extend(part)

    if len(data) >= limit:
        raise ValueError(
            "Server response exceeded the configured line limit."
        )

    return bytes(data)


def _send_json_frame(sock, magic: bytes, payload: dict):
    body = json.dumps(
        payload,
        ensure_ascii=False
    ).encode("utf-8")

    if not 1 <= len(body) <= 4096:
        raise ValueError(
            "Application metadata frame is outside the allowed size."
        )

    sock.sendall(
        magic + struct.pack("!I", len(body)) + body
    )


@st.cache_data(show_spinner=False)
def _media_duration(path: Path, kind: str):
    """Return media duration in seconds where a parser is available."""

    if kind == "audio":
        try:
            with wave.open(str(path), "rb") as wav:
                rate = wav.getframerate()

                return (
                    wav.getnframes() / rate
                    if rate else None
                )

        except (wave.Error, OSError):
            return None

    # MP4 duration requires optional ffprobe.
    for executable in ("ffprobe", "ffprobe.exe"):
        try:
            result = subprocess.run(
                [
                    executable,
                    "-v", "error",
                    "-show_entries", "format=duration",
                    "-of",
                    "default=noprint_wrappers=1:nokey=1",
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                return float(result.stdout.strip())

        except (
            OSError,
            ValueError,
            subprocess.SubprocessError
        ):
            continue

    return None


def _check_tls_ready():
    sock = st.session_state.get("tls_sock")

    if (
        sock is None
        or st.session_state.stage < 2
        or st.session_state.closed
    ):
        raise RuntimeError(
            "Connect TCP and complete the TLS handshake "
            "before sending data."
        )

    if st.session_state.get("pending_operation") is not None:
        raise RuntimeError(
            "Receive the pending server result before "
            "starting another operation."
        )

    return sock


def _send_text_operation(message: str, reply: str):
    sock = _check_tls_ready()

    message = message.strip()
    reply = reply.strip()

    if not message or not reply:
        raise ValueError(
            "Enter both the text message and expected server reply."
        )

    if (
        "\n" in message or "\r" in message
        or "\n" in reply or "\r" in reply
    ):
        raise ValueError(
            "Use a single line for the message and reply."
        )

    _save_reply_rule(message, reply)

    started = time.time()
    message_bytes = message.encode("utf-8")

    _send_json_frame(
        sock,
        TEXT_MAGIC,
        {
            "type": "text",
            "message": message
        }
    )

    elapsed = max(time.time() - started, 1e-6)

    st.session_state.response = ""

    st.session_state.pending_operation = {
        "type": "text",
        "filename": None,
        "size": len(message_bytes),
        "duration": None,
        "started": started,
    }

    st.session_state.last_transfer = {
        "mode": "Text",
        "filename": "Text message",
        "size_bytes": len(message_bytes),
        "media_duration": None,
        "send_duration": elapsed,
        "throughput_mbps": (
            len(message_bytes) * 8 / elapsed / 1_000_000
        ),
        "metadata_packet": {
            "type": "text",
            "encoding": "UTF-8",
            "payload_bytes": len(message_bytes),
        },
        "status": "Sent; waiting for Receive click",
    }

    st.session_state.sent_at = time.strftime("%H:%M:%S")
    st.session_state.stage = 3

    _record_window(
        "text_send",
        started,
        time.time()
    )


def _send_media_operation(kind: str, path: Path):
    sock = _check_tls_ready()

    if kind not in ("audio", "video"):
        raise ValueError("Unsupported media type.")

    if not path.is_file():
        raise FileNotFoundError(
            f"Selected media file not found: {path}"
        )

    size = path.stat().st_size

    if not 1 <= size <= MAX_MEDIA_BYTES:
        raise ValueError(
            "Media file must be between 1 byte and 100 MiB."
        )

    expected_ext = (
        ".wav" if kind == "audio" else ".mp4"
    )

    if path.suffix.lower() != expected_ext:
        raise ValueError(
            f"Select a {expected_ext} file for {kind} transmission."
        )

    with path.open("rb") as check:
        header_bytes = check.read(12)

    if kind == "audio" and not (
        header_bytes.startswith(b"RIFF")
        and header_bytes[8:12] == b"WAVE"
    ):
        raise ValueError(
            "Selected file does not have a valid WAV RIFF/WAVE header."
        )

    if kind == "video" and (
        len(header_bytes) < 8
        or header_bytes[4:8] != b"ftyp"
    ):
        raise ValueError(
            "Selected file does not have an MP4 ftyp container header."
        )

    media_duration = _media_duration(path, kind)

    metadata = {
        "type": kind,
        "filename": path.name,
        "size": size,
        "duration_seconds": media_duration,
    }

    header = json.dumps(
        metadata,
        ensure_ascii=False
    ).encode("utf-8")

    if len(header) > 4096:
        raise ValueError(
            "Media metadata header is too large."
        )

    started = time.time()

    sock.sendall(
        MEDIA_MAGIC
        + struct.pack("!I", len(header))
        + header
    )

    sent = 0

    with path.open("rb") as media_file:
        while True:
            chunk = media_file.read(64 * 1024)

            if not chunk:
                break

            sock.sendall(chunk)
            sent += len(chunk)

    if sent != size:
        raise IOError(
            f"File changed during transmission: "
            f"expected {size} bytes, sent {sent} bytes."
        )

    elapsed = max(time.time() - started, 1e-6)

    st.session_state.response = ""

    st.session_state.pending_operation = {
        "type": kind,
        "filename": path.name,
        "size": size,
        "duration": media_duration,
        "started": started,
    }

    st.session_state.last_transfer = {
        "mode": kind.title(),
        "filename": path.name,
        "size_bytes": size,
        "media_duration": media_duration,
        "send_duration": elapsed,
        "throughput_mbps": (
            size * 8 / elapsed / 1_000_000
        ),
        "metadata_packet": {
            "type": kind,
            "filename": path.name,
            "format": expected_ext[1:].upper(),
            "payload_bytes": size,
            "duration_seconds": media_duration,
        },
        "status": "Sent; waiting for Receive click",
    }

    st.session_state.sent_at = time.strftime("%H:%M:%S")
def _save_reply_rule(question: str, reply: str):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        rules = json.loads(
            RULES_FILE.read_text(encoding="utf-8")
        )

        if not isinstance(rules, dict):
            rules = {}

    except (OSError, json.JSONDecodeError):
        rules = {}

    rules[question.strip().casefold()] = reply

    RULES_FILE.write_text(
        json.dumps(
            rules,
            indent=4,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )


def _record_window(name, started, ended):
    windows = st.session_state.get("stage_windows", {})

    windows[name] = {
        "start": started,
        "end": ended,
    }

    st.session_state.stage_windows = windows



def _preflight_checks():
    """Run local, read-only checks on the configured certificate files."""
    checks = []
    for label, path in (("CA certificate exists", CA_FILE),
                        ("Server certificate exists", BASE_DIR / "certificates" / "server.crt"),
                        ("Server private key exists", BASE_DIR / "certificates" / "server.key")):
        checks.append({"Check": label, "Status": "PASS" if path.is_file() else "FAIL",
                       "Details": str(path) if path.is_file() else f"Missing: {path}"})

    ca_path = CA_FILE
    cert_path = BASE_DIR / "certificates" / "server.crt"
    key_path = BASE_DIR / "certificates" / "server.key"
    if ca_path.is_file() and cert_path.is_file():
        try:
            # Python/OpenSSL parses the PEM certificate and exposes its fields.
            ca_info = ssl._ssl._test_decode_cert(str(ca_path))
            cert_info = ssl._ssl._test_decode_cert(str(cert_path))
            checks.append({"Check": "CA certificate readable", "Status": "PASS",
                           "Details": f"Subject={ca_info.get('subject', ())}"})
            checks.append({"Check": "Server certificate readable", "Status": "PASS",
                           "Details": f"Subject={cert_info.get('subject', ())}; issuer={cert_info.get('issuer', ())}"})
            sans = [value for kind, value in cert_info.get("subjectAltName", ()) if kind == "DNS"]
            host_ok = SERVER_HOSTNAME in sans
            checks.append({"Check": f"Hostname SAN includes {SERVER_HOSTNAME}",
                           "Status": "PASS" if host_ok else "FAIL",
                           "Details": f"DNS SAN values: {sans or 'none found'}"})
            try:
                not_before = ssl.cert_time_to_seconds(cert_info["notBefore"])
                not_after = ssl.cert_time_to_seconds(cert_info["notAfter"])
                now = time.time()
                valid = not_before <= now <= not_after
                checks.append({"Check": "Server certificate currently within validity dates",
                               "Status": "PASS" if valid else "FAIL",
                               "Details": f"Not before: {cert_info['notBefore']}; not after: {cert_info['notAfter']}"})
            except Exception as exc:
                checks.append({"Check": "Certificate validity dates", "Status": "UNKNOWN", "Details": str(exc)})
        except Exception as exc:
            checks.append({"Check": "Certificate PEM parsing", "Status": "FAIL", "Details": str(exc)})

    # Verify the CA signature chain and certificate/key pairing when OpenSSL is available.
    openssl = None
    for candidate in ("openssl", "openssl.exe"):
        try:
            found = subprocess.run([candidate, "version"], capture_output=True, text=True, timeout=3)
            if found.returncode == 0:
                openssl = candidate
                break
        except (OSError, subprocess.SubprocessError):
            continue
    if openssl and ca_path.is_file() and cert_path.is_file():
        try:
            result = subprocess.run([openssl, "verify", "-CAfile", str(ca_path), str(cert_path)],
                                    capture_output=True, text=True, timeout=5)
            checks.append({"Check": "Server certificate verifies against ca.crt",
                           "Status": "PASS" if result.returncode == 0 else "FAIL",
                           "Details": (result.stdout + result.stderr).strip()})
        except Exception as exc:
            checks.append({"Check": "CA signature/chain verification", "Status": "UNKNOWN", "Details": str(exc)})
        if key_path.is_file():
            try:
                cert_pub = subprocess.run([openssl, "x509", "-in", str(cert_path), "-pubkey", "-noout"],
                                          capture_output=True, text=True, timeout=5)
                key_pub = subprocess.run([openssl, "pkey", "-in", str(key_path), "-pubout"],
                                         capture_output=True, text=True, timeout=5)
                match = cert_pub.returncode == 0 and key_pub.returncode == 0 and cert_pub.stdout.strip() == key_pub.stdout.strip()
                checks.append({"Check": "server.crt matches server.key", "Status": "PASS" if match else "FAIL",
                               "Details": "Public keys match" if match else "Could not confirm matching public keys; inspect OpenSSL output and key format."})
            except Exception as exc:
                checks.append({"Check": "Certificate/private-key pairing", "Status": "UNKNOWN", "Details": str(exc)})
    else:
        checks.append({"Check": "CA signature and certificate/key pairing", "Status": "UNKNOWN",
                       "Details": "OpenSSL executable not found; install/configure OpenSSL to run these cryptographic checks."})
    return checks


def _run_live_certificate_test(hostname, trust_mode="project_ca"):
    """Attempt a real TLS handshake and return whether the expected result occurred."""
    raw = None
    tls = None
    try:
        if trust_mode == "project_ca":
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_FILE))
        else:
            # Deliberately empty trust store: this test should reject our private-CA certificate.
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection((HOST, PORT), timeout=3)
        raw.settimeout(3)
        tls = ctx.wrap_socket(raw, server_hostname=hostname)
        return True, f"Handshake succeeded: {tls.version()} / {tls.cipher()[0]}"
    except ssl.SSLCertVerificationError as exc:
        return False, f"Certificate validation rejected the connection: {exc}"
    except Exception as exc:
        return False, f"Connection/test could not complete: {type(exc).__name__}: {exc}"
    finally:
        try:
            if tls is not None:
                tls.close()
            elif raw is not None:
                raw.close()
        except OSError:
            pass


def _find_tshark():
    candidates = [
        Path(TSHARK_DEFAULT),
        Path(r"C:\Program Files\Wireshark\tshark.exe"),
        Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
    ]

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return "tshark"


def _stop_process(proc):
    if proc is None:
        return

    try:
        if proc.poll() is None:
            proc.terminate()

            try:
                proc.wait(timeout=3)

            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

    except (OSError, subprocess.SubprocessError):
        pass


def _stop_capture():
    """Stop both TShark processes and close their output handles."""

    for key in ("capture_proc", "pcap_proc"):
        proc = st.session_state.get(key)
        _stop_process(proc)
        st.session_state[key] = None

    for key in (
        "capture_out_handle",
        "capture_err_handle",
        "pcap_err_handle",
    ):
        handle = st.session_state.get(key)

        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass

            st.session_state[key] = None

    st.session_state.capture_status = "Stopped"


def _start_capture(interface_id="8"):
    """Start full packet capture and a separate live field parser."""

    if st.session_state.get("capture_proc") is not None:
        if st.session_state.capture_proc.poll() is None:
            return

    tshark = _find_tshark()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    capture_file = RESULTS_DIR / "capture.pcapng"
    live_file = RESULTS_DIR / "live_tshark_packets.txt"
    capture_error = RESULTS_DIR / "tshark_capture_error.txt"
    parser_error = RESULTS_DIR / "tshark_parser_error.txt"

    for path in (
        capture_file,
        live_file,
        capture_error,
        parser_error,
    ):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    capture_error_handle = capture_error.open(
        "w",
        encoding="utf-8"
    )

    parser_error_handle = parser_error.open(
        "w",
        encoding="utf-8"
    )

    capture_command = [
        tshark,
        "-i", str(interface_id),
        "-f", "tcp port 8443",
        "-w", str(capture_file),
    ]

    parser_command = [
        tshark,
        "-l",
        "-n",
        "-i", str(interface_id),
        "-f", "tcp port 8443",
        "-T", "fields",
        "-E", "separator=|",
        "-E", "quote=n",
        "-E", "occurrence=f",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.time",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.stream",
        "-e", "tcp.flags",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tcp.flags.fin",
        "-e", "tcp.flags.reset",
        "-e", "tcp.seq",
        "-e", "tcp.ack",
        "-e", "tcp.window_size_value",
        "-e", "tcp.hdr_len",
        "-e", "tcp.len",
        "-e", "tcp.payload",
        "-e", "tls.record.content_type",
        "-e", "tls.record.length",
        "-e", "tcp.analysis.retransmission",
        "-e", "tcp.analysis.fast_retransmission",
        "-e", "tcp.analysis.lost_segment",
        "-e", "tcp.analysis.duplicate_ack",
    ]

    try:
        pcap_proc = subprocess.Popen(
            capture_command,
            stdout=subprocess.DEVNULL,
            stderr=capture_error_handle,
            creationflags=getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0
            ),
        )

        parser_proc = subprocess.Popen(
            parser_command,
            stdout=live_file.open(
                "w",
                encoding="utf-8"
            ),
            stderr=parser_error_handle,
            creationflags=getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0
            ),
        )

    except Exception:
        capture_error_handle.close()
        parser_error_handle.close()
        raise

    st.session_state.pcap_proc = pcap_proc
    st.session_state.capture_proc = parser_proc

    st.session_state.pcap_err_handle = capture_error_handle
    st.session_state.capture_err_handle = parser_error_handle

    st.session_state.capture_file = str(capture_file)
    st.session_state.pcap_file = str(capture_file)

    st.session_state.pcap_err_file = str(capture_error)
    st.session_state.capture_err_file = str(parser_error)

    st.session_state.capture_status = (
        f"Capturing on interface {interface_id}"
    )


def _tcp_connect():
    if st.session_state.get("tls_sock") is not None:
        raise RuntimeError(
            "A connection already exists. Close or reset it first."
        )

    started = time.time()

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(10)

    try:
        sock.connect((HOST, PORT))

    except Exception:
        sock.close()
        raise

    st.session_state.tls_sock = sock
    st.session_state.stage = 1

    st.session_state.connection_started_epoch = started
    st.session_state.connection_ended_epoch = None

    st.session_state.tcp_local = str(sock.getsockname())
    st.session_state.tcp_peer = str(sock.getpeername())

    st.session_state.client_port = str(
        sock.getsockname()[1]
    )

    st.session_state.closed = False

    _record_window(
        "tcp_connect",
        started,
        time.time()
    )


def _tls_handshake():
    sock = st.session_state.get("tls_sock")

    if sock is None:
        raise RuntimeError(
            "Establish TCP connection before TLS handshake."
        )

    if st.session_state.stage != 1:
        raise RuntimeError(
            "TLS handshake can only happen after TCP connection."
        )

    started = time.time()

    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=str(CA_FILE)
    )

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    tls_sock = context.wrap_socket(
        sock,
        server_hostname=SERVER_HOSTNAME
    )

    tls_sock.settimeout(30)

    st.session_state.tls_sock = tls_sock
    st.session_state.stage = 2

    st.session_state.tls_version = tls_sock.version()

    cipher_info = tls_sock.cipher()

    st.session_state.cipher = (
        cipher_info[0] if cipher_info else "Unknown"
    )

    _record_window(
        "tls_handshake",
        started,
        time.time()
    )


def _close_connection():
    sock = st.session_state.get("tls_sock")

    if sock is None:
        return

    close_started = time.time()

    try:
        sock.settimeout(3)

        # Initiate TLS shutdown (close_notify)
        raw_sock = sock.unwrap()
        raw_sock.close()

    except Exception as exc:
        st.warning(f"TLS shutdown: {exc}")

        try:
            sock.close()
        except Exception:
            pass

    finally:
        close_ended = time.time()

        # Record the connection-close packet window
        _record_window(
            "connection_close",
            close_started,
            close_ended
        )

        st.session_state["tls_sock"] = None
        st.session_state["tcp_sock"] = None
        st.session_state["stage"] = 0


def _reset_communication():
    _stop_capture()

    sock = st.session_state.get("tls_sock")

    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass

    for key, value in DEFAULTS.items():
        st.session_state[key] = value
def _receive_pending_operation():
    sock = _check_tls_receive_ready()

    operation = st.session_state.get("pending_operation")

    if operation is None:
        raise RuntimeError(
            "There is no pending operation to receive."
        )

    kind = operation["type"]
    started = time.time()

    # Tell the server to release the pending result.
    sock.sendall(RECEIVE_MAGIC)

    response_line = _recv_line_tls(sock)

    if not response_line:
        raise ConnectionError(
            "The server closed the connection without a response."
        )

    result = json.loads(response_line.decode("utf-8"))

    if not result.get("ok"):
        raise RuntimeError(
            result.get("error", "Server returned an error.")
        )

    if kind == "text":
        server_response = result.get("response", "")

        if not isinstance(server_response, str):
            raise ValueError("Invalid text response from server.")

        st.session_state.response = server_response

    elif kind in ("audio", "video"):
        received_media = {
            "type": kind,
            "saved_as": result.get("saved_as"),
            "bytes": result.get("bytes"),
        }

        st.session_state.received_media.append(received_media)

    else:
        raise ValueError("Unknown pending operation type.")

    elapsed = time.time() - started

    st.session_state.received_at = time.strftime("%H:%M:%S")
    st.session_state.pending_operation = None
    st.session_state.stage = 4

    st.session_state.last_transfer["receive_duration"] = elapsed
    st.session_state.last_transfer["status"] = "Received from server"

    _record_window(
        f"{kind}_receive",
        started,
        time.time()
    )


def _check_tls_receive_ready():
    sock = st.session_state.get("tls_sock")

    if (
        sock is None
        or st.session_state.stage < 2
        or st.session_state.closed
    ):
        raise RuntimeError(
            "A valid TLS connection is required."
        )

    if st.session_state.pending_operation is None:
        raise RuntimeError(
            "No pending operation is available to receive."
        )

    return sock


def _parse_packet_line(line):
    """
    Parse one pipe-separated TShark record.

    Field order:
    frame number, epoch, time, frame length,
    IP source/destination, TCP source/destination ports,
    stream, flags, SYN, ACK, FIN, RST,
    sequence, acknowledgement, window, TCP header length,
    TCP payload length, TCP payload, TLS content type,
    TLS record length, retransmission, fast retransmission,
    lost segment, duplicate ACK.
    """

    fields = line.rstrip("\r\n").split("|")

    if len(fields) < 26:
        return None

    def number(index, default=0):
        try:
            return int(fields[index], 0)
        except (ValueError, TypeError):
            try:
                return int(float(fields[index]))
            except (ValueError, TypeError):
                return default

    def flag(index):
        return fields[index].strip() in ("1", "True", "true")

    try:
        epoch = float(fields[1])
    except (ValueError, TypeError):
        epoch = 0.0

    return {
        "frame": number(0),
        "epoch": epoch,
        "time": fields[2],
        "frame_len": number(3),
        "src": fields[4],
        "dst": fields[5],
        "src_port": fields[6],
        "dst_port": fields[7],
        "stream": fields[8],
        "flags": fields[9],
        "syn": flag(10),
        "ack_flag": flag(11),
        "fin": flag(12),
        "rst": flag(13),
        "seq": fields[14],
        "ack": fields[15],
        "window": fields[16],
        "tcp_header_len": fields[17],
        "tcp_len": number(18),
        "payload": fields[19],
        "tls_content_type": fields[20],
        "tls_record_len": fields[21],
        "retransmission": flag(22),
        "fast_retransmission": flag(23),
        "lost_segment": flag(24),
        "duplicate_ack": flag(25),
    }


def _read_live_packets():
    path = RESULTS_DIR / "live_tshark_packets.txt"

    if not path.is_file():
        return []

    rows = []

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            for line in file:
                row = _parse_packet_line(line)

                if row is not None:
                    rows.append(row)

    except OSError:
        return []

    return rows


def _get_connection_stream(rows):
    stream_id = st.session_state.get("connection_stream_id")

    if stream_id is not None:
        return str(stream_id)

    local_port = st.session_state.get("client_port")

    if not local_port:
        return None

    for row in rows:
        if (
            row["src_port"] == local_port
            or row["dst_port"] == local_port
        ):
            stream_id = row["stream"]

            st.session_state.connection_stream_id = stream_id

            return str(stream_id)

    return None


def _get_window(name):
    return st.session_state.get(
        "stage_windows",
        {}
    ).get(name)


def _rows_for_mode(rows, mode):
    """Filter packet records for the selected operation."""

    stream_id = _get_connection_stream(rows)

    if stream_id is None:
        return []

    selected = [
        row for row in rows
        if str(row["stream"]) == stream_id
    ]

    if mode == "tcp":
        return selected

    if mode == "tls":
        return [
            row for row in selected
            if row["tls_content_type"]
            or row["tls_record_len"]
        ]

    if mode == "close":
        return [
            row for row in selected
            if row["fin"] or row["rst"]
        ]

    # Operation-specific windows.
    window = _get_window(mode)

    if window is None:
        return []

    start = window["start"] - 0.5
    end = window["end"] + 0.5

    selected = [
        row for row in selected
        if start <= row["epoch"] <= end
    ]

    if mode.endswith("_send"):
        return [
            row for row in selected
            if row["src_port"] == st.session_state.client_port
        ]

    if mode.endswith("_receive"):
        return [
            row for row in selected
            if row["dst_port"] == st.session_state.client_port
        ]

    return selected
def _format_bytes(value):
    value = float(value)

    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{value:.2f} TB"


def _packet_direction(row):
    local_port = st.session_state.client_port

    if row["src_port"] == local_port:
        return "Client → Server"

    if row["dst_port"] == local_port:
        return "Server → Client"

    return "Unknown"


def _packet_type(row):
    if row["rst"]:
        return "TCP RESET"

    if row["fin"]:
        return "TCP FIN"

    if row["syn"]:
        return "TCP SYN"

    if row["tls_content_type"]:
        return "TLS Record"

    if row["tcp_len"] > 0:
        return "TCP Data"

    return "TCP Control"


def _packet_table(rows):
    if not rows:
        st.info(
            "No packets are available for this selection yet. "
            "Check that TShark is capturing on the correct interface."
        )
        return

    table = []

    for row in rows:
        table.append({
            "Frame": row["frame"],
            "Time": row["time"],
            "Direction": _packet_direction(row),
            "Type": _packet_type(row),
            "Source": f'{row["src"]}:{row["src_port"]}',
            "Destination": f'{row["dst"]}:{row["dst_port"]}',
            "Frame bytes": row["frame_len"],
            "TCP payload": row["tcp_len"],
            "TLS record": row["tls_record_len"],
            "TCP Seq": row["seq"],
            "TCP Ack": row["ack"],
            "Window": row["window"],
            "Retransmission": (
                "Yes" if row["retransmission"] else "No"
            ),
        })

    st.dataframe(
        table,
        use_container_width=True,
        hide_index=True,
    )


def _encrypted_payload_view(rows):
    st.subheader("Encrypted TLS packet data")

    st.caption(
        "This displays captured TCP payload bytes in hexadecimal. "
        "After the TLS handshake, application data is encrypted. "
        "This is ciphertext/wire data, not the original plaintext."
    )

    payload_rows = [
        row for row in rows
        if row["payload"]
    ]

    if not payload_rows:
        st.info(
            "No TCP payload bytes were found in the selected packet window."
        )
        return

    for row in payload_rows[-8:]:
        with st.expander(
            f'Frame {row["frame"]} | '
            f'{_packet_direction(row)} | '
            f'{_format_bytes(row["tcp_len"])}'
        ):
            hex_value = row["payload"].replace(":", " ").strip()

            st.code(
                hex_value if hex_value else "(No payload)",
                language="text"
            )

            st.write(
                {
                    "Frame number": row["frame"],
                    "Frame length": row["frame_len"],
                    "TCP payload length": row["tcp_len"],
                    "TCP sequence number": row["seq"],
                    "TCP acknowledgement number": row["ack"],
                    "TCP window": row["window"],
                    "TLS record length": row["tls_record_len"],
                    "Retransmission": row["retransmission"],
                }
            )


def _show_transfer_metrics():
    transfer = st.session_state.get("last_transfer", {})

    if not transfer:
        st.info(
            "Send a text message or media file to see transfer metadata."
        )
        return

    st.subheader("Transfer metadata")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Operation",
        transfer.get("mode", "-")
    )

    col2.metric(
        "Payload size",
        _format_bytes(transfer.get("size_bytes", 0))
    )

    col3.metric(
        "Send duration",
        f'{transfer.get("send_duration", 0):.4f} s'
    )

    col4.metric(
        "Throughput",
        f'{transfer.get("throughput_mbps", 0):.4f} Mbps'
    )

    duration = transfer.get("media_duration")

    if duration is not None:
        st.write(
            f"**Media duration:** {duration:.3f} seconds"
        )

    receive_duration = transfer.get("receive_duration")

    if receive_duration is not None:
        st.write(
            f"**Receive acknowledgement time:** "
            f"{receive_duration:.4f} seconds"
        )

    st.write(
        f'**File/message:** {transfer.get("filename", "-")}'
    )

    st.write(
        f'**Status:** {transfer.get("status", "-")}'
    )

    with st.expander("Application metadata header"):
        st.json(
            transfer.get("metadata_packet", {})
        )


def _show_received_media():
    received = st.session_state.get("received_media", [])

    if not received:
        return

    st.subheader("Files received by server")

    for item in reversed(received):
        st.write(
            f'**{item["type"].title()} file:** '
            f'{item.get("saved_as", "Unknown")}'
        )

        st.write(
            f'**Received size:** '
            f'{_format_bytes(item.get("bytes", 0))}'
        )

        if item["type"] == "audio":
            path = STORAGE_AUDIO_DIR / item["saved_as"]

            if path.is_file():
                st.audio(
                    str(path),
                    format="audio/wav"
                )

        elif item["type"] == "video":
            path = STORAGE_VIDEO_DIR / item["saved_as"]

            if path.is_file():
                st.video(str(path))


def _show_capture_status():
    proc = st.session_state.get("capture_proc")

    if proc is not None and proc.poll() is not None:
        st.warning(
            "The live TShark parser process has stopped. "
            "Check the parser error log."
        )

    pcap_proc = st.session_state.get("pcap_proc")

    if pcap_proc is not None and pcap_proc.poll() is not None:
        st.warning(
            "The PCAP writer process has stopped. "
            "Check the capture error log."
        )

    st.caption(
        f'Capture status: {st.session_state.capture_status}'
    )
# ============================================================
# MAIN DASHBOARD
# ============================================================

st.title("Communication Dashboard")

# ------------------------------------------------------------
# 1. Connection status
# ------------------------------------------------------------

stage = st.session_state.stage

status_col1, status_col2, status_col3 = st.columns(3)

with status_col1:
    if stage == 0:
        st.info("TCP: Not connected")
    else:
        st.success("TCP: Connected")

with status_col2:
    if stage < 2:
        st.info("TLS: Not established")
    else:
        st.success(
            f'TLS: {st.session_state.tls_version}'
        )

with status_col3:
    if st.session_state.pending_operation:
        st.warning("Operation: Waiting for Receive")
    elif stage >= 4:
        st.success("Operation: Completed")
    else:
        st.info("Operation: Ready")


# ------------------------------------------------------------
# 2. Communication architecture
# ------------------------------------------------------------

st.subheader("Communication Architecture")

col1, col2, col3 = st.columns([2, 1, 2])

with col1:
    st.markdown(
        """
        <div class="device">
            <div class="device-icon">💻</div>
            <div class="device-name">TLS Client</div>
            <div class="device-sub">Streamlit dashboard</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        """
        <div style="text-align:center;padding-top:45px;">
            <div style="font-size:30px;">🔒</div>
            <div style="font-weight:bold;">TLS</div>
            <div class="muted">Encrypted channel</div>
            <div style="font-size:25px;">⇄</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        """
        <div class="device server">
            <div class="device-icon">🖥️</div>
            <div class="device-name">TLS Server</div>
            <div class="device-sub">Python socket server</div>
        </div>
        """,
        unsafe_allow_html=True,
    )



# ------------------------------------------------------------
# 3. TLS certificate readiness and verification
# ------------------------------------------------------------

st.subheader("TLS Certificate Readiness and Verification")
st.caption(
    "Run each preparation check independently from the dashboard. "
    "Live tests make short TLS handshake attempts against the running server "
    "at 127.0.0.1:8443."
)

# Each preparation button runs the local, read-only preflight routine and
# displays only the result(s) related to the selected check.
preparation_checks = [
    {
        "title": "Certificate Availability",
        "description": "Checks that the CA certificate, server certificate, "
                       "and server private key files are present.",
        "names": [
            "CA certificate exists",
            "Server certificate exists",
            "Server private key exists",
        ],
    },
    {
        "title": "Certificate Parsing",
        "description": "Checks whether the CA and server certificates can be "
                       "read and parsed as PEM certificates.",
        "names": [
            "CA certificate readable",
            "Server certificate readable",
            "Certificate PEM parsing",
        ],
    },
    {
        "title": "Hostname Verification",
        "description": f"Checks whether the certificate contains "
                       f"'{SERVER_HOSTNAME}' in its DNS Subject Alternative Name.",
        "names": [f"Hostname SAN includes {SERVER_HOSTNAME}"],
    },
    {
        "title": "Certificate Validity",
        "description": "Checks whether the server certificate is currently "
                       "within its not-before and not-after validity dates.",
        "names": [
            "Server certificate currently within validity dates",
            "Certificate validity dates",
        ],
    },
    {
        "title": "CA Trust Verification",
        "description": "Uses OpenSSL to verify that the server certificate "
                       "chains to the configured CA certificate.",
        "names": [
            "Server certificate verifies against ca.crt",
            "CA signature/chain verification",
        ],
    },
    {
        "title": "Certificate and Key Matching",
        "description": "Compares the public key in server.crt with the public "
                       "key derived from server.key.",
        "names": [
            "server.crt matches server.key",
            "Certificate/private-key pairing",
        ],
    },
]


def _run_one_preparation_check(check):
    all_results = _preflight_checks()
    selected = [
        item for item in all_results
        if item.get("Check") in check["names"]
    ]

    # If OpenSSL is unavailable, the preflight function reports one combined
    # UNKNOWN result. Surface that limitation in the relevant crypto checks.
    if not selected and check["title"] in (
        "CA Trust Verification",
        "Certificate and Key Matching",
    ):
        combined = next(
            (
                item for item in all_results
                if item.get("Check")
                == "CA signature and certificate/key pairing"
            ),
            None,
        )
        if combined:
            selected = [{
                "Check": check["title"],
                "Status": "UNKNOWN",
                "Details": combined["Details"],
            }]

    if not selected:
        selected = [{
            "Check": check["title"],
            "Status": "UNKNOWN",
            "Details": "The selected check did not produce a result. "
                       "Review the certificate files and preflight function.",
        }]

    previous = st.session_state.get("certificate_preflight") or []
    # Replace only the selected category's previous results.
    retained = [
        item for item in previous
        if item.get("Check") not in check["names"]
        and not (
            item.get("Check") == check["title"]
            and check["title"] in (
                "CA Trust Verification",
                "Certificate and Key Matching",
            )
        )
    ]
    st.session_state.certificate_preflight = retained + selected
    st.session_state["last_preparation_check"] = check["title"]


st.markdown("### Individual Preparation Checks")
st.caption(
    "Choose a check to run it and view its result. These checks inspect local "
    "certificate files; they do not establish a network connection."
)

for row_start in range(0, len(preparation_checks), 3):
    check_columns = st.columns(3)
    for offset, check in enumerate(
        preparation_checks[row_start:row_start + 3]
    ):
        with check_columns[offset]:
            st.markdown(f"**{check['title']}**")
            st.caption(check["description"])
            if st.button(
                "Run Check",
                key=f"prep_{row_start + offset}",
                use_container_width=True,
            ):
                _run_one_preparation_check(check)

preflight = st.session_state.get("certificate_preflight") or []
if preflight:
    passed = sum(item.get("Status") == "PASS" for item in preflight)
    failed = sum(item.get("Status") == "FAIL" for item in preflight)
    unknown = sum(item.get("Status") == "UNKNOWN" for item in preflight)

    metric_a, metric_b, metric_c = st.columns(3)
    metric_a.metric("Passed results", passed)
    metric_b.metric("Failed results", failed)
    metric_c.metric("Not verified", unknown)

    with st.expander("View preparation-check results", expanded=True):
        for item in preflight:
            status = item.get("Status", "UNKNOWN")
            icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚪"
            st.markdown(f"**{icon} {item.get('Check', 'Check')} — {status}**")
            st.write(item.get("Details", "No details returned."))
else:
    st.info("No preparation checks have been run yet. Select any Run Check button above.")


st.divider()
st.markdown("### Individual Live TLS Certificate Tests")
st.caption(
    "Start server.py before running these tests. Each button performs one "
    "real TLS handshake attempt. The negative tests should be rejected by "
    "certificate verification."
)


def _execute_one_tls_test(test_name, hostname, trust_mode, expected):
    ok, detail = _run_live_certificate_test(hostname, trust_mode)

    if expected == "PASS":
        result = "PASS" if ok else "FAIL"
    else:
        rejected = (
            not ok
            and "certificate validation rejected" in detail.lower()
        )
        result = "REJECTED as expected" if rejected else "UNEXPECTED"

    new_result = {
        "Test case": test_name,
        "Expected": expected,
        "Result": result,
        "Details": detail,
        "Hostname used": hostname,
        "Trust mode": trust_mode,
    }

    previous = st.session_state.get("certificate_test_results", [])
    st.session_state.certificate_test_results = [
        item for item in previous
        if item.get("Test case") != test_name
    ] + [new_result]


live_test_columns = st.columns(3)

with live_test_columns[0]:
    st.markdown("**1. Valid Certificate Test**")
    st.caption(
        "Uses the project CA and the correct hostname 'localhost'. "
        "The TLS handshake should succeed."
    )
    if st.button(
        "Run Valid Certificate Test",
        key="test_valid_certificate",
        use_container_width=True,
    ):
        _execute_one_tls_test(
            "Valid CA + correct hostname",
            SERVER_HOSTNAME,
            "project_ca",
            "PASS",
        )

with live_test_columns[1]:
    st.markdown("**2. Wrong Hostname Test**")
    st.caption(
        "Uses 'wrong-hostname.invalid' while trusting the project CA. "
        "Hostname verification should reject the handshake."
    )
    if st.button(
        "Run Wrong Hostname Test",
        key="test_wrong_hostname",
        use_container_width=True,
    ):
        _execute_one_tls_test(
            "Wrong hostname",
            "wrong-hostname.invalid",
            "project_ca",
            "REJECT",
        )

with live_test_columns[2]:
    st.markdown("**3. Untrusted Certificate Test**")
    st.caption(
        "Uses the correct hostname but an empty trust store. "
        "The issuing CA is not trusted, so verification should reject it."
    )
    if st.button(
        "Run Untrusted Certificate Test",
        key="test_untrusted_certificate",
        use_container_width=True,
    ):
        _execute_one_tls_test(
            "Untrusted CA / empty trust store",
            SERVER_HOSTNAME,
            "empty_trust",
            "REJECT",
        )

test_results = st.session_state.get("certificate_test_results", [])
if test_results:
    with st.expander("View live TLS test results", expanded=True):
        for item in test_results:
            result = item.get("Result", "UNKNOWN")
            good = result in ("PASS", "REJECTED as expected")
            icon = "✅" if good else "❌"
            st.markdown(
                f"**{icon} {item.get('Test case')} — {result}**"
            )
            st.write(f"Expected outcome: {item.get('Expected')}")
            st.write(f"Hostname used: {item.get('Hostname used', '-')}")
            st.write(f"Trust configuration: {item.get('Trust mode', '-')}")
            st.write(item.get("Details", "No details returned."))

    st.caption(
        "A wrong-hostname or untrusted-CA test is successful when TLS "
        "specifically rejects the certificate. These tests do not modify "
        "the certificate files. Expired-certificate and mismatched-key live "
        "tests require separate test certificate fixtures."
    )
else:
    st.info(
        "No live TLS tests have been run. Start server.py, then select one "
        "of the three test buttons. These tests do not send application data."
    )


# ============================================================
# CERTIFICATE VERIFICATION - CONTENT ORIENTED DISPLAY
# ============================================================

st.divider()
st.subheader("Certificate Verification Workflow")

st.caption(
    "Understand how the system validates certificates "
    "before and during TLS connection establishment."
)

preflight = st.session_state.get("certificate_preflight")
test_results = st.session_state.get("certificate_test_results", [])


def verification_card(title, description, status="NOT RUN"):

    status_colors = {
        "PASS": "#16A34A",
        "FAIL": "#DC2626",
        "UNKNOWN": "#D97706",
        "NOT RUN": "#64748B",
        "REJECTED as expected": "#16A34A",
        "UNEXPECTED": "#DC2626",
    }

    color = status_colors.get(status, "#64748B")

    st.markdown(
        f"""
        <div style="
            border:1px solid {color};
            border-radius:10px;
            padding:13px;
            margin-bottom:10px;
            background:rgba(100,116,139,0.07);
        ">
            <div style="display:flex;justify-content:space-between;gap:10px;">
                <b>{html.escape(title)}</b>
                <span style="color:{color};font-weight:700;font-size:12px;">
                    {html.escape(status)}
                </span>
            </div>
            <div style="
                margin-top:7px;
                color:#AABBD0;
                font-size:13px;
                line-height:1.5;
            ">
                {html.escape(description)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ------------------------------------------------------------
# PREPARATION CHECKS
# ------------------------------------------------------------

st.markdown("### 1. Preparation Checks")

st.caption(
    "Local inspection of certificate information and trust configuration."
)

preparation_descriptions = [
    (
        "Certificate Availability",
        "Checks whether the trusted CA certificate, server certificate "
        "and private key are available.",
        ["CA certificate exists", "Server certificate exists",
         "Server private key exists"],
    ),
    (
        "Certificate Parsing",
        "Reads certificate information, including subject, issuer "
        "and certificate details.",
        ["CA certificate readable", "Server certificate readable"],
    ),
    (
        "Hostname Verification",
        "Checks whether the server certificate contains the expected "
        "hostname in its Subject Alternative Name.",
        [f"Hostname SAN includes {SERVER_HOSTNAME}"],
    ),
    (
        "Certificate Validity",
        "Checks whether the certificate is currently within its "
        "validity period.",
        ["Server certificate currently within validity dates"],
    ),
    (
        "CA Trust Verification",
        "Verifies the server certificate using the configured "
        "trusted Certificate Authority.",
        ["Server certificate verifies against ca.crt"],
    ),
    (
        "Certificate and Key Matching",
        "Checks whether the public key in the server certificate "
        "matches the public key derived from the private key.",
        ["server.crt matches server.key"],
    ),
]

prep_cols = st.columns(2)

for index, (title, description, check_names) in enumerate(
    preparation_descriptions
):
    matching = [
        item for item in (preflight or [])
        if item.get("Check") in check_names
    ]

    if not preflight:
        status = "NOT RUN"
    elif any(item.get("Status") == "FAIL" for item in matching):
        status = "FAIL"
    elif any(item.get("Status") == "UNKNOWN" for item in matching):
        status = "UNKNOWN"
    elif matching and all(
        item.get("Status") == "PASS" for item in matching
    ):
        status = "PASS"
    elif not matching:
        status = "UNKNOWN"
    else:
        status = "NOT RUN"

    with prep_cols[index % 2]:
        verification_card(title, description, status)


# ------------------------------------------------------------
# Certificate Test Cases
# ------------------------------------------------------------

# ------------------------------------------------------------
# Certificate Test Cases - INDIVIDUAL EXECUTION
# ------------------------------------------------------------

st.divider()
st.markdown("### 2. Certificate Test Cases")

st.caption(
    "Run each TLS certificate test independently. "
    "The result will update the corresponding workflow card."
)

live_descriptions = [
    (
        "Valid CA + Correct Hostname",
        "Uses the trusted CA certificate and correct hostname. "
        "The TLS handshake should succeed.",
        "PASS",
        SERVER_HOSTNAME,
        "project_ca",
        "run_valid_cert",
    ),
    (
        "Wrong Hostname",
        "Uses an incorrect hostname. TLS hostname verification "
        "should reject the connection.",
        "REJECT",
        "wrong-hostname.invalid",
        "project_ca",
        "run_wrong_hostname",
    ),
    (
        "Untrusted CA / Empty Trust Store",
        "Uses an empty trust store. Certificate verification "
        "should reject the connection.",
        "REJECT",
        SERVER_HOSTNAME,
        "empty_trust",
        "run_untrusted_ca",
    ),
]

# Create three individual test buttons
button_columns = st.columns(3)

for index, test in enumerate(live_descriptions):

    case_name, description, expected, hostname, trust_mode, button_key = test

    with button_columns[index]:

        if st.button(
            f"Run {case_name}",
            key=button_key,
            use_container_width=True,
        ):

            with st.spinner(f"Running {case_name}..."):

                ok, detail = _run_live_certificate_test(
                    hostname,
                    trust_mode,
                )

            if expected == "PASS":
                result_status = "PASS" if ok else "FAIL"

            else:
                rejected = (
                    not ok
                    and "certificate validation rejected"
                    in detail.lower()
                )

                result_status = (
                    "REJECTED as expected"
                    if rejected
                    else "UNEXPECTED"
                )

            # Preserve previous test results
            previous_results = [
                item
                for item in st.session_state.get(
                    "certificate_test_results", []
                )
                if item.get("Test case") != case_name
            ]

            previous_results.append({
                "Test case": case_name,
                "Expected": expected,
                "Result": result_status,
                "Details": detail,
            })

            st.session_state.certificate_test_results = previous_results

            if result_status in ("PASS", "REJECTED as expected"):
                st.success(f"{case_name}: {result_status}")
            else:
                st.error(f"{case_name}: {result_status}")

# Read updated results AFTER button execution
test_results = st.session_state.get(
    "certificate_test_results", []
)

# Display updated workflow cards
st.markdown("#### Test Execution Results")

for case_name, description, expected, hostname, trust_mode, button_key in live_descriptions:

    result = next(
        (
            item for item in test_results
            if item.get("Test case", "").casefold()
            == case_name.casefold()
        ),
        None,
    )

    status = result.get("Result", "NOT RUN") if result else "NOT RUN"

    verification_card(
        case_name,
        description,
        status,
    )

    if result:
        with st.expander(f"View details: {case_name}"):

            st.write(f"Expected: {result['Expected']}")
            st.write(f"Actual result: {result['Result']}")
            st.write(f"Hostname: {hostname}")
            st.write(f"Trust mode: {trust_mode}")
            st.code(result["Details"])

if not test_results:
    st.info(
        "No live tests have been executed. "
        "Start server.py and run an individual test."
    )



# ------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------

if preflight or test_results:

    st.divider()
    st.markdown("### Verification Summary")

    prep_passed = sum(
        item.get("Status") == "PASS"
        for item in (preflight or [])
    )

    prep_failed = sum(
        item.get("Status") == "FAIL"
        for item in (preflight or [])
    )

    live_success = sum(
        item.get("Result") in ("PASS", "REJECTED as expected")
        for item in test_results
    )

    col1, col2, col3 = st.columns(3)

    col1.metric("Preparation Passed", prep_passed)
    col2.metric("Preparation Failed", prep_failed)
    col3.metric(
        "Live Tests Successful",
        f"{live_success}/{len(test_results)}"
    )

# ------------------------------------------------------------
# 4. Sidebar settings
# ------------------------------------------------------------

with st.sidebar:
    st.header("Project Settings")

    st.write(f"Server: `{HOST}:{PORT}`")
    st.write(f"TLS hostname: `{SERVER_HOSTNAME}`")

    st.divider()

    st.subheader("TShark Capture")

    interface_id = st.text_input(
        "Capture interface ID",
        value="8",
        help="Your Npcap loopback interface ID is 8."
    )

    if st.button(
        "Start TShark Capture",
        use_container_width=True,
        disabled=(
            st.session_state.get("capture_proc") is not None
            and st.session_state.capture_proc.poll() is None
        ),
    ):
        try:
            _start_capture(interface_id.strip())
            st.success("TShark capture started.")

        except Exception as exc:
            st.error(f"Capture error: {exc}")

    if st.button(
        "Stop TShark Capture",
        use_container_width=True,
    ):
        _stop_capture()
        st.success("Capture stopped.")

    _show_capture_status()

    st.divider()

    st.subheader("Communication Control")

    if st.button(
        "Reset Communication",
        use_container_width=True,
    ):
        _reset_communication()
        st.rerun()


# ------------------------------------------------------------
# 5. TCP and TLS connection sequence
# ------------------------------------------------------------

st.subheader("Establish Secure Connection")

connection_col1, connection_col2 = st.columns(2)

with connection_col1:
    if st.button(
        "1. TCP Connect",
        use_container_width=True,
        disabled=st.session_state.stage != 0,
    ):
        try:
            _tcp_connect()
            st.success("TCP connection established.")

        except Exception as exc:
            st.session_state.last_error = str(exc)
            st.error(f"TCP connection failed: {exc}")

with connection_col2:
    if st.button(
        "2. TLS Handshake",
        use_container_width=True,
        disabled=st.session_state.stage != 1,
    ):
        try:
            _tls_handshake()
            st.success("TLS handshake completed.")

        except Exception as exc:
            st.session_state.last_error = str(exc)
            st.error(f"TLS handshake failed: {exc}")


if st.session_state.stage >= 1:
    st.write("**TCP local endpoint:**", st.session_state.tcp_local)
    st.write("**TCP server endpoint:**", st.session_state.tcp_peer)

if st.session_state.stage >= 2:
    st.success(
        f"Secure connection established using "
        f"{st.session_state.tls_version}"
    )

    st.write("**Cipher suite:**", st.session_state.cipher)


# ------------------------------------------------------------
# 5. Select one transmission mode
# ------------------------------------------------------------

st.divider()

st.subheader("Select Transmission Mode")

mode = st.radio(
    "Choose one operation at a time:",
    ["Text", "Voice (WAV)", "Video (MP4)"],
    horizontal=True,
    key="selected_transmission_mode",
    disabled=(
        st.session_state.stage < 2
        or st.session_state.pending_operation is not None
    ),
)

# ------------------------------------------------------------
# 6. Text transmission
# ------------------------------------------------------------

if mode == "Text":
    st.subheader("Text Communication")

    message = st.text_area(
        "Message to server",
        value=st.session_state.request,
        height=100,
        key="text_message_input",
        disabled=(
            st.session_state.pending_operation is not None
        ),
    )

    expected_reply = st.text_area(
        "Configure server reply for this message",
        value=st.session_state.server_reply,
        height=100,
        key="text_reply_input",
        disabled=(
            st.session_state.pending_operation is not None
        ),
    )

    if st.button(
        "Send Text to Server",
        type="primary",
        use_container_width=True,
        disabled=(
            st.session_state.stage < 2
            or st.session_state.pending_operation is not None
        ),
    ):
        try:
            _send_text_operation(
                message,
                expected_reply
            )

            st.success(
                "Text sent through TLS. "
                "Click Receive from Server to obtain the response."
            )

        except Exception as exc:
            st.error(f"Text transmission failed: {exc}")


# ------------------------------------------------------------
# 7. Voice transmission
# ------------------------------------------------------------

elif mode == "Voice (WAV)":
    st.subheader("Voice Communication")

    AUDIO_DIR.mkdir(
        parents=True,
        exist_ok=True
    )
    
    audio_files = _list_media_files(
        AUDIO_DIR,
        ".wav"
    )

    if not audio_files:
        st.warning(
            f"No WAV files found in: {AUDIO_DIR}"
        )

    else:
        selected_audio = st.selectbox(
            "Select audio file",
            audio_files,
            format_func=lambda p: p.name,
        )

        if selected_audio:
            st.write(
                f"**Selected:** {selected_audio.name}"
            )

            st.write(
                f"**Size:** "
                f"{_format_bytes(selected_audio.stat().st_size)}"
            )

            duration = _media_duration(
                selected_audio,
                "audio"
            )

            if duration is not None:
                st.write(
                    f"**Duration:** {duration:.3f} seconds"
                )

            st.audio(
                str(selected_audio),
                format="audio/wav"
            )

            if st.button(
                "Send Voice to Server",
                type="primary",
                use_container_width=True,
                disabled=(
                    st.session_state.stage < 2
                    or st.session_state.pending_operation is not None
                ),
            ):
                try:
                    _send_media_operation(
                        "audio",
                        selected_audio
                    )

                    st.success(
                        "Voice file sent through TLS. "
                        "Click Receive from Server to get the acknowledgement."
                    )

                except Exception as exc:
                    st.error(
                        f"Voice transmission failed: {exc}"
                    )


# ------------------------------------------------------------
# 8. Video transmission
# ------------------------------------------------------------

elif mode == "Video (MP4)":
    st.subheader("Video Communication")

    VIDEO_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    video_files = _list_media_files(
        VIDEO_DIR,
        ".mp4"
    )

    if not video_files:
        st.warning(
            f"No MP4 files found in: {VIDEO_DIR}"
        )

    else:
        selected_video = st.selectbox(
            "Select video file",
            video_files,
            format_func=lambda p: p.name,
        )

        if selected_video:
            st.write(
                f"**Selected:** {selected_video.name}"
            )

            st.write(
                f"**Size:** "
                f"{_format_bytes(selected_video.stat().st_size)}"
            )

            duration = _media_duration(
                selected_video,
                "video"
            )

            if duration is not None:
                st.write(
                    f"**Duration:** {duration:.3f} seconds"
                )
            else:
                st.caption(
                    "Install FFmpeg and add ffprobe to PATH "
                    "to calculate MP4 duration."
                )

            st.video(str(selected_video))

            if st.button(
                "Send Video to Server",
                type="primary",
                use_container_width=True,
                disabled=(
                    st.session_state.stage < 2
                    or st.session_state.pending_operation is not None
                ),
            ):
                try:
                    _send_media_operation(
                        "video",
                        selected_video
                    )

                    st.success(
                        "Video file sent through TLS. "
                        "Click Receive from Server to get the acknowledgement."
                    )

                except Exception as exc:
                    st.error(
                        f"Video transmission failed: {exc}"
                    )


# ------------------------------------------------------------
# 9. Explicit Receive operation
# ------------------------------------------------------------

st.divider()

st.subheader("Receive Server Result")

pending = st.session_state.pending_operation

if pending is not None:
    st.warning(
        f'Pending operation: {pending["type"].upper()} '
        f'| Size: {_format_bytes(pending["size"])}'
    )

    st.info(
        "The server has not released the application response yet. "
        "Click the button below to request it."
    )

    if st.button(
        "Receive from Server",
        type="primary",
        use_container_width=True,
    ):
        try:
            _receive_pending_operation()

            st.success(
                "Server result received successfully."
            )

        except Exception as exc:
            st.error(
                f"Receive operation failed: {exc}"
            )

else:
    st.info(
        "No pending server response. Send one operation first."
    )


# ------------------------------------------------------------
# 10. Display received text response
# ------------------------------------------------------------

if st.session_state.response:
    st.subheader("Server Text Response")

    st.success(
        st.session_state.response
    )


# ------------------------------------------------------------
# 11. Transfer metadata
# ------------------------------------------------------------

st.divider()

_show_transfer_metrics()

_show_received_media()


# ------------------------------------------------------------
# 12. TShark packet inspection
# ------------------------------------------------------------

st.divider()

st.title("Network Packet Analysis")

st.caption(
    "Packets are captured from the selected Npcap interface. "
    "The application filters them using the active TCP stream, "
    "operation time window and direction."
)

packet_modes = {
    "All TCP packets": "tcp",
    "TLS records": "tls",
    "Text — Client to Server": "text_send",
    "Text — Server to Client": "text_receive",
    "Voice — Client to Server": "audio_send",
    "Voice — Server to Client": "audio_receive",
    "Video — Client to Server": "video_send",
    "Video — Server to Client": "video_receive",
    "Connection close": "close",
}

selected_packet_label = st.selectbox(
    "Select packet category",
    list(packet_modes.keys()),
    key="packet_category_selector",
)

selected_packet_mode = packet_modes[
    selected_packet_label
]


# ------------------------------------------------------------
# Display packets ONLY when TShark capture is running
# ------------------------------------------------------------

capture_process = st.session_state.get("capture_proc")

capture_is_running = (
    capture_process is not None
    and capture_process.poll() is None
)

if capture_is_running:
    # Read packets only during active capture
    rows = _read_live_packets()

    filtered_rows = _rows_for_mode(
        rows,
        selected_packet_mode
    )
else:
    # Keep packet display empty before/after capture
    rows = []
    filtered_rows = []

# Packet metrics
metric1, metric2, metric3 = st.columns(3)

metric1.metric(
    "Captured packets",
    len(rows)
)

metric2.metric(
    "Filtered packets",
    len(filtered_rows)
)

total_bytes = sum(
    row["frame_len"]
    for row in filtered_rows
)

metric3.metric(
    "Filtered frame bytes",
    _format_bytes(total_bytes)
)

st.subheader(
    f"Packet details — {selected_packet_label}"
)

if capture_is_running:
    _packet_table(filtered_rows)

    _encrypted_payload_view(filtered_rows)
else:
    st.info(
        "TShark capture is not running. "
        "Click 'Start TShark Capture' to display packets."
    )



# ------------------------------------------------------------
# 13. Full packet capture file
# ------------------------------------------------------------

st.divider()

st.subheader("Full Packet Capture")

capture_path = st.session_state.get("capture_file")

if capture_path and Path(capture_path).is_file():
    path = Path(capture_path)

    st.success(
        f"PCAPNG file available: {path.name}"
    )

    st.write(
        f"**File size:** {_format_bytes(path.stat().st_size)}"
    )

    try:
        st.download_button(
            "Download captured PCAPNG",
            data=path.read_bytes(),
            file_name="capture.pcapng",
            mime="application/octet-stream",
            use_container_width=True,
        )

    except OSError as exc:
        st.error(
            f"Could not read capture file: {exc}"
        )

else:
    st.info(
        "Start TShark capture to create the PCAPNG file."
    )


# ------------------------------------------------------------
# 14. Connection close
# ------------------------------------------------------------

st.divider()

st.subheader("Close Connection")

if st.button(
    "Close TLS Connection",
    use_container_width=True,
    disabled=(
        st.session_state.tls_sock is None
        or st.session_state.closed
    ),
):
    try:
        _close_connection()

        st.success(
            "TLS connection closed."
        )

    except Exception as exc:
        st.error(
            f"Connection close error: {exc}"
        )


# ------------------------------------------------------------
# 15. Error and diagnostic information
# ------------------------------------------------------------

if st.session_state.last_error:
    st.error(
        st.session_state.last_error
    )

with st.expander("Diagnostic information"):
    st.write(
        {
            "Dashboard stage": st.session_state.stage,
            "TLS version": st.session_state.tls_version,
            "Cipher suite": st.session_state.cipher,
            "TCP client port": st.session_state.client_port,
            "TCP stream ID": st.session_state.connection_stream_id,
            "Pending operation": (
                st.session_state.pending_operation
            ),
            "Capture status": st.session_state.capture_status,
        }
    )

    if st.session_state.get("capture_err_file"):
        error_path = Path(
            st.session_state.capture_err_file
        )

        if error_path.is_file():
            st.caption("TShark parser error log")

            st.code(
                error_path.read_text(
                    encoding="utf-8",
                    errors="replace"
                )[-4000:]
            )

    if st.session_state.get("pcap_err_file"):
        error_path = Path(
            st.session_state.pcap_err_file
        )

        if error_path.is_file():
            st.caption("TShark capture error log")

            st.code(
                error_path.read_text(
                    encoding="utf-8",
                    errors="replace"
                )[-4000:]
            )