#!/usr/bin/env python3
"""Solver for Challenge 347 chrono (picoCTF 2023, General Skills).

SSH lab (picoplayer@chatelaine.cylabacademy.net:<port>, password from the
instance description). Classic cron-hunting: no user crontab, but the flag
sits in cleartext as a comment inside /etc/crontab.

Lab is on-demand (PUT /api/challenges/347/instance/); host:port rotates.
Usage: solve_347_chrono.py [host] [port] [password]
Verified: academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823} (POST /api/submissions/ -> correct:true)
"""
import re
import subprocess
import sys

HOST = "chatelaine.cylabacademy.net"
PORT = 25769
PASSWORD = "0SlcDTpc5Y"
EXPECTED = "academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}"

FLAG_RE = re.compile(r"academy\{[^}]*\}")


def solve(host: str = HOST, port: int = PORT, password: str = PASSWORD,
          timeout: int = 30) -> str:
    cmd = ["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=15", "-p", str(port),
           "picoplayer@%s" % host, "cat /etc/crontab"]
    out = subprocess.run(cmd, capture_output=True, text=True,
                         timeout=timeout).stdout
    m = FLAG_RE.search(out)
    assert m, "flag not found in /etc/crontab: %r" % out[:300]
    flag = m.group(0)
    print("flag:", flag)
    assert flag == EXPECTED, flag
    return EXPECTED


if __name__ == "__main__":
    a = sys.argv[1:]
    print(solve(a[0] if len(a) > 0 else HOST,
                int(a[1]) if len(a) > 1 else PORT,
                a[2] if len(a) > 2 else PASSWORD))
