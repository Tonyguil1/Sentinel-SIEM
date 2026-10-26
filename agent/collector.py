import subprocess
import json


def collect_ssh_logs():
    command = [
        "journalctl",
        "-u", "ssh.service",
        "-f",
        "-n", "0",
        "-o", "json",
        "--no-pager"
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    try:
        for line in process.stdout:
            try:
                event = json.loads(line)
                yield event
            except json.JSONDecodeError:
                continue
    finally:
        process.terminate()
        process.wait()
