#!/usr/bin/env python3
"""
Solver for Challenge 15: mus1c (General Skills)
Runs the Rockstar lyrics via rockstar-py 2.1.0 after normalizing
the dialect (keyword case, pronoun resolution, multi-increment split),
then decodes the ASCII number output.
"""
import os
import re
import subprocess
import sys
import tarfile
import time
import urllib.request

VENDOR_DIR = os.path.join(os.path.expanduser("~"), ".cache",
                          "rockstar-py-vendor")
SDIST_URL = ("https://files.pythonhosted.org/packages/04/bf/"
             "6efc04e878fc6beb5309410f148970d44ee58ebebe60e28b9fb7012548da/"
             "rockstar-py-2.1.0.tar.gz")


def ensure_rockstar_py():
    """Unpack rockstar-py sdist to a cache dir and return its path."""
    dest = os.path.join(VENDOR_DIR, "rockstar-py-2.1.0")
    if not os.path.isdir(os.path.join(dest, "rockstarpy")):
        os.makedirs(VENDOR_DIR, exist_ok=True)
        arc = os.path.join(VENDOR_DIR, "rockstar-py-2.1.0.tar.gz")
        req = urllib.request.Request(SDIST_URL,
                                     headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as resp, \
                open(arc, "wb") as fh:
            fh.write(resp.read())
        with tarfile.open(arc) as tar:
            tar.extractall(VENDOR_DIR)
    return dest

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


URL = ("https://challenge-files.cylabacademy.net/library/"
       "d67c9614df4e4d89b88fd6b36560c74a0644cd3ecc3b9c82af762568eb7c875d/"
       "mus1c-lyrics.txt")
PRONOUNS = {"it", "him", "her", "them", "they", "he", "she"}


def clean_var(v):
    v = v.strip()
    m = re.match(r"(?i)^(an?|the|my|your)\s+([a-z]+)$", v)
    if m:
        return m.group(1).lower() + "_" + m.group(2).lower()
    return re.sub(r"\s+", "_", v)


def normalize(src):
    src = src.replace("my flag is not found", "My flag is vague")
    src = re.sub(r"\bsecurity\b", "Security", src)
    src = re.sub(r"(?<![A-Za-z])fun(?![A-Za-z])", "Fun", src)
    # capitalize leading keywords
    lines = []
    for raw in src.splitlines():
        s = raw.strip()
        m = re.match(r"(?i)^(put|knock|build|shout)\b(.*)$", s)
        if m:
            s = m.group(1).capitalize() + m.group(2)
        s = re.sub(r"\bmy_song\b", "my song", s)
        lines.append(s)
    # resolve left-side pronouns + split multi increments
    last, out = None, []
    for s in lines:
        if not s:
            out.append("")
            continue
        m = re.match(r"(?i)^(build|knock)\s+(it|him|her|them|they|he|she)\s+"
                     r"(up|down)((?:\s*,\s*(?:up|down))*)\s*$", s)
        if m and last:
            out.append(f"{m.group(1).capitalize()} {last} "
                       f"{m.group(3)}{m.group(4)}")
        elif re.match(r"(?i)^shout\s+(it|him|her|them|they|he|she)\s*$", s) and last:
            out.append(f"Shout {last}")
        else:
            m2 = re.match(r"(?i)^(build\s+.+?)\s+up((?:\s*,\s*up)+)\s*$", s)
            if m2:
                n = m2.group(2).lower().count("up")
                base = m2.group(1)
                base = base[0].upper() + base[1:]
                out.extend([f"{base} up"] * (n + 1))
            else:
                out.append(s)
        t = out[-1]
        for pat in [r"(?i)^put\s+.+?\s+into\s+(.+?)\s*$",
                    r"(?i)^(.+?)\s+(?:is|was|are|were)\s+.+$",
                    r"(.+?)'s\s+(?:a\s+)?.+$"]:
            mm = re.match(pat, t)
            if mm:
                cand = mm.group(1).strip()
                if cand.lower() not in PRONOUNS:
                    last = clean_var(cand)
                break
    return "\n".join(out) + "\n"


def solve(url=URL):
    lyrics = fetch(url).decode()
    norm_src = normalize(lyrics)
    with open("/tmp/mus1c_batch12.rock", "w") as fh:
        fh.write(norm_src)
    rock = norm_src
    pkgdir = ensure_rockstar_py()
    proc = subprocess.run(
        [sys.executable, "-m", "rockstarpy", "--stdin", "--exec"],
        input=rock, capture_output=True, text=True, timeout=60,
        cwd=pkgdir, env={"PATH": "/usr/bin:/bin",
                         "PYTHONPATH": pkgdir})
    if proc.returncode != 0:
        raise RuntimeError(f"rockstarpy failed: {proc.stderr[-500:]}")
    nums = [int(x) for x in proc.stdout.split()]
    if len(nums) < 5:
        raise RuntimeError(f"unexpected rockstar output: {proc.stdout!r}")
    inner = "".join(chr(n) for n in nums)
    return f"academy{{{inner}}}"


if __name__ == "__main__":
    print("Flag:", solve())
