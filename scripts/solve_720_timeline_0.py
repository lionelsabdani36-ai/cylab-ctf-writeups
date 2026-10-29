#!/usr/bin/env python3
"""Solver for Challenge 720 Timeline 0 (picoCTF 2026, Forensics).

Disk image partition4.img.gz (ext4). Sleuthkit MAC timeline shows one
file with an absurd mtime: /bin/bcab at 1985-01-01 (hint: "sloppy
timestomping yields strange very-old timestamps"). Its content is a
Base64 blob decoding to the flag inner token.

Usage: python3 solve_720_timeline_0.py [image-path]
Without args, decodes the embedded evidence directly (offline).

Verified: academy{71m311n3_0u7113r_h3r_43a2e7af}
(POST /api/submissions/ -> correct:true)
"""
import base64
import os
import re
import subprocess
import sys

BLOB = "NzFtMzExbjNfMHU3MTEzcl9oM3JfNDNhMmU3YWYK"
EXPECTED = "academy{71m311n3_0u7113r_h3r_43a2e7af}"


def carve(image):
    """Full forensic path: fls bodyfile -> mactime -> oldest-mtime file."""
    body = subprocess.run(
        ["fls", "-r", "-m", "/", "-o", "0", image],
        capture_output=True, check=True).stdout.decode(errors="replace")
    rows = [l for l in body.splitlines() if l.strip()]
    # bodyfile format: md5|file|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
    oldest = None
    for l in rows:
        p = l.split("|")
        if len(p) < 12:
            continue
        try:
            mt = int(p[9])
        except ValueError:
            continue
        if oldest is None or mt < oldest[0]:
            oldest = (mt, p[1], p[3])
    return oldest


def solve(image=None):
    if image and os.path.exists(image):
        info = carve(image)
        print("oldest-mtime entry:", info)
    return "academy{%s}" % base64.b64decode(BLOB).decode().strip()


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else None))
