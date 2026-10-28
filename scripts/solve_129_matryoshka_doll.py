#!/usr/bin/env python3
"""
Solver for Challenge 129: Matryoshka doll (Forensics)
Recursively carves embedded ZIP archives (magic PK\\x03\\x04)
appended after each PNG IEND chunk, up to 12 layers deep,
until the flag text surfaces.
"""
import io
import re
import time
import urllib.request
import zipfile

URL = ("https://challenge-files.cylabacademy.net/library/"
       "a268db7b2edb5615a738f69c2c79faa4d8a6bcde6b0c2f2f797a8f319cb52fe2a5/"
       "dolls.jpg")

REQ_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/133.0.0.0 Safari/537.36"),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://learn.cylabacademy.org/challenges",
}


def fetch(url, timeout=60, tries=5):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=REQ_HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except Exception as e:
            last = e
            time.sleep(10 * (i + 1))
    raise RuntimeError(f"fetch failed after {tries} tries: {last}")


def solve(url=URL, max_depth=12):
    cur = fetch(url)
    for _ in range(max_depth):
        idxs = [m.start() for m in re.finditer(b"PK\x03\x04", cur)]
        if not idxs:
            break
        progressed = False
        for idx in idxs:
            try:
                z = zipfile.ZipFile(io.BytesIO(cur[idx:]))
            except Exception:
                continue
            nxt = z.read(z.namelist()[0])
            m = re.search(rb"(academy\{[^}]*\}|picoCTF\{[^}]*\})", nxt)
            if m:
                return m.group(1).decode()
            cur = nxt
            progressed = True
            break
        if not progressed:
            break
    m = re.search(rb"(academy\{[^}]*\}|picoCTF\{[^}]*\})", cur)
    return m.group(1).decode() if m else None


if __name__ == "__main__":
    print("Flag:", solve())
