import json
import socket
from datetime import datetime, timezone

from collector import collect_ssh_logs
from parser import parse_ssh_event


def main():
    hostname = socket.gethostname()

    print(f"Sentinel agent started on {hostname}")

    with open("security_events.jsonl", "a") as file:

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
                ).isoformat()
            else:
                event_time = None

            event = {
                "timestamp": event_time,
                "hostname": hostname,
                "service": "sshd",
                **parsed_event
            }

            file.write(json.dumps(event) + "\n")
            file.flush()

            print(json.dumps(event, indent=2))


if __name__ == "__main__":
    main()
