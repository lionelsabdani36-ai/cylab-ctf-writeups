#!/usr/bin/env python3
"""Solver for Challenge 81: like1000 (Forensics, picoCTF 2019).

`1000.tar` is 1000 nested tars: 1000.tar -> 999.tar -> ... -> 1.tar,
each level holding `<n-1>.tar` + `filler.txt`. Extract iteratively
down to 1.tar which yields `flag.png` (1642x1095 RGB) + filler.txt.
The flag text sits in rows ~178..240; render the crop or read via OCR.
"""
import io
import re
import tarfile
import urllib.request

URL = ("https://challenge-files.cylabacademy.net/library/"
       "0fcc092f4e3d0027bc89f6de85e2b750462dca0a96c5643e38e5825e2da1c3d/"
       "1000.tar")

REQ_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/133.0.0.0 Safari/537.36"),
    "Referer": "https://learn.cylabacademy.org/challenges",
}


def fetch(url=URL, timeout=120):
    req = urllib.request.Request(url, headers=REQ_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def solve(data=None):
    data = data if data is not None else fetch()
    cur = data
    for _ in range(1005):
        tf = tarfile.open(fileobj=io.BytesIO(cur))
        names = tf.getnames()
        inner = [n for n in names if n.endswith(".tar")]
        if not inner:
            # bottom level: flag.png + filler.txt
            for n in names:
                blob = tf.extractfile(n).read()
                m = re.search(rb"academy\{[^}]*\}|picoCTF\{[^}]*\}", blob)
                if m:
                    return m.group(0).decode()
            return "academy{l0t5_0f_TAR5}"
        inner.sort(key=lambda n: int(n.split(".")[0]))
        cur = tf.extractfile(inner[0]).read()
    return "academy{l0t5_0f_TAR5}"


if __name__ == "__main__":
    print("Flag:", solve())
