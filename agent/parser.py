import re

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from "
    r"(?P<ip>\S+) port (?P<port>\d+)"
)

SUCCESS_PATTERN = re.compile(
    r"Accepted \S+ for "
    r"(?P<username>\S+) from "
    r"(?P<ip>\S+) port (?P<port>\d+)"
)


def parse_ssh_event(message):
    failed = FAILED_PATTERN.search(message)

    if failed:
        return {
            "event_type": "ssh_login_failed",
            "username": failed.group("username"),
            "source_ip": failed.group("ip"),
            "source_port": int(failed.group("port"))
        }

    success = SUCCESS_PATTERN.search(message)

    if success:
        return {
            "event_type": "ssh_login_success",
            "username": success.group("username"),
            "source_ip": success.group("ip"),
            "source_port": int(success.group("port"))
        }

    return None
