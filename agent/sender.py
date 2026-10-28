import json
import os
import urllib.error
import urllib.request

API_URL = os.environ.get("SENTINEL_API_URL", "http://127.0.0.1:8000")
API_KEY = os.environ.get("SENTINEL_API_KEY", "")
SPOOL_PATH = os.environ.get("SENTINEL_SPOOL_PATH", "pending_events.jsonl")
TIMEOUT_SECONDS = 5


class RejectedEvent(Exception):
    """The backend refused the event itself, so retrying won't help."""


def post_event(event):
    request = urllib.request.Request(
        f"{API_URL}/events",
        data=json.dumps(event).encode(),
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS):
            pass
    except urllib.error.HTTPError as error:
        if error.code in (400, 422):
            raise RejectedEvent(
                f"backend rejected event: HTTP {error.code}"
            ) from error
        raise


def spool_event(event):
    with open(SPOOL_PATH, "a") as file:
        file.write(json.dumps(event) + "\n")


def flush_spool():
    """Resend spooled events in order.

    Returns True once the spool is empty.
    """
    if not os.path.exists(SPOOL_PATH):
        return True

    with open(SPOOL_PATH) as file:
        pending = [line for line in file if line.strip()]

    sent = 0

    for line in pending:
        try:
            post_event(json.loads(line))
        except (RejectedEvent, json.JSONDecodeError) as error:
            print(f"Dropping spooled event: {error}")
        except OSError:
            break

        sent += 1

    remaining = pending[sent:]

    if not remaining:
        os.remove(SPOOL_PATH)
        return True

    temp_path = SPOOL_PATH + ".tmp"

    with open(temp_path, "w") as file:
        file.writelines(remaining)

    os.replace(temp_path, SPOOL_PATH)
    return False


def send_event(event):
    # Older events go first so the backend receives them in order.
    if not flush_spool():
        spool_event(event)
        return

    try:
        post_event(event)
    except RejectedEvent as error:
        print(f"Dropping event: {error}")
    except OSError as error:
        print(f"Backend unavailable ({error}), spooling event")
        spool_event(event)
