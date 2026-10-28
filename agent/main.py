import json
import os
import socket
import sys
from datetime import datetime, timezone

from collector import collect_ssh_logs
from parser import parse_ssh_event
from sender import send_event


def main():
    if not os.environ.get("SENTINEL_API_KEY"):
        sys.exit("SENTINEL_API_KEY is not set")

    hostname = socket.gethostname()

    print(f"Sentinel agent started on {hostname}")

    for log in collect_ssh_logs():
        message = log.get("MESSAGE", "")

        if not isinstance(message, str):
            continue

        parsed_event = parse_ssh_event(message)

        if parsed_event is None:
            continue

        timestamp = log.get(
            "__REALTIME_TIMESTAMP"
        )

        if timestamp:
            event_time = datetime.fromtimestamp(
                int(timestamp) / 1_000_000,
                tz=timezone.utc
            )
        else:
            event_time = datetime.now(timezone.utc)

        event = {
            "timestamp": event_time.isoformat(),
            "hostname": hostname,
            "service": "sshd",
            **parsed_event
        }

        print(json.dumps(event, indent=2))

        send_event(event)


if __name__ == "__main__":
    main()
