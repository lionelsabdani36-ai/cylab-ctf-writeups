#!/usr/bin/env python3
"""Solver for Challenge 721 Timeline 1 (picoCTF 2026, Forensics).

Disk image timeline-1-partition4.img.gz (ext4). Sleuthkit MAC timeline,
filtered to `macb` entries (hint: "filter only new files by grepping
macb"), shows the most recent attacker activity on Dec 01 2025 ~21:42:
package installs followed by an anti-forensic step. /root/.ash_history
contains only "poweroff". The file /etc/chat (macb 21:50:07) holds a
Base64 blob decoding to the flag inner token.

Usage: python3 solve_721_timeline_1.py [image-path]
Without args, decodes the embedded evidence directly (offline).

Verified: academy{573417h13r_7h4n_7h3_1457_58527bb222}
(POST /api/submissions/ -> correct:true)
"""
import base64
import os
import subprocess
import sys

BLOB = "NTczNDE3aDEzcl83aDRuXzdoM18xNDU3XzU4NTI3YmIyMjIK"
EXPECTED = "academy{573417h13r_7h4n_7h3_1457_58527bb222}"


def recent_macb(image):
    tl = subprocess.run(
        ["sh", "-c", f"fls -r -m / -o 0 {image} | mactime -d -b -"],
        capture_output=True, check=True).stdout.decode(errors="replace")
    rows = [l for l in tl.splitlines() if ",macb," in l]
    rows.sort(reverse=True)
    return rows[:5]


def solve(image=None):
    if image and os.path.exists(image):
        for r in recent_macb(image):
            print(r[:160])
    return "academy{%s}" % base64.b64decode(BLOB).decode().strip()


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else None))
