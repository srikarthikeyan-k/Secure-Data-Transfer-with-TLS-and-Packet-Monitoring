
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
EVENT_FILE = BASE_DIR / "results" / "dashboard_events.jsonl"

_lock = threading.Lock()


def emit_event(event_type, message, **details):
    """
    Append one real backend event to the JSONL event history.
    Safe for multiple local Python processes writing to one file.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "message": message,
        **details,
    }

    EVENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(event, default=str) + "\n"

    with _lock:
        with EVENT_FILE.open("a", encoding="utf-8") as file:
            file.write(line)
            file.flush()

    return event


def clear_events():
    """Clear the dashboard event history before a new demonstration."""
    EVENT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with _lock:
        EVENT_FILE.write_text("", encoding="utf-8")
