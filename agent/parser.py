import re

# Usernames are attacker-controlled and may contain spaces, so each
# pattern is anchored to the end of the line and matches the username
# greedily. That way the IP and port always come from the last
# "from <ip> port <port>" in the line, which sshd itself wrote, and
# a username like "x from 6.6.6.6 port 1" can't spoof the source.
PATTERNS = [
    (
        "ssh_login_success",
        re.compile(
            r"^Accepted \S+ for (?P<username>.*) "
            r"from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2.*)?$"
        )
    ),
    (
        # Covers password, publickey, keyboard-interactive/pam, none
        "ssh_login_failed",
        re.compile(
            r"^Failed \S+ for (?:invalid user )?(?P<username>.*) "
            r"from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2.*)?$"
        )
    ),
    (
        # Unknown username, logged even if no password is ever tried
        "ssh_invalid_user",
        re.compile(
            r"^Invalid user (?P<username>.*) "
            r"from (?P<ip>\S+) port (?P<port>\d+)$"
        )
    ),
    (
        "ssh_max_auth_exceeded",
        re.compile(
            r"^(?:error: )?maximum authentication attempts exceeded "
            r"for (?:invalid user )?(?P<username>.*) "
            r"from (?P<ip>\S+) port (?P<port>\d+) ssh2 \[preauth\]$"
        )
    ),
    (
        # Client gave up before authenticating. On key-only servers
        # this is often the only trace of a failed login attempt.
        "ssh_preauth_disconnect",
        re.compile(
            r"^(?:Connection closed by|Disconnected from) "
            r"(?:invalid|authenticating) user (?P<username>.*) "
            r"(?P<ip>\S+) port (?P<port>\d+) \[preauth\]$"
        )
    ),
]


def parse_ssh_event(message):
    for event_type, pattern in PATTERNS:
        match = pattern.match(message)

        if match:
            return {
                "event_type": event_type,
                # Scanners sometimes send an empty username
                "username": match.group("username") or None,
                "source_ip": match.group("ip"),
                "source_port": int(match.group("port"))
            }

    return None
