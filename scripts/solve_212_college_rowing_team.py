#!/usr/bin/env python3
"""Solver for Challenge 212: college-rowing-team (picoMini by redpwn, Cryptography, Hard).

NIST SP 800-115 / RFC 8017 Håstad's Broadcast Attack on Low Public Exponent RSA:
The challenge simulates broadcasting 4 distinct messages (including the flag), each encrypted
3 times with e = 3 under distinct 2048-bit RSA moduli (p * q):
  c_i = m^3 mod n_i   for i in {1, 2, 3}

Cryptanalysis (Håstad Broadcast Attack via Chinese Remainder Theorem):
When the same cleartext message m is encrypted under k >= e coprime moduli n_1, ..., n_k:
  1. We apply CRT to find C mod N (where N = n_1 * ... * n_k) such that:
     C = c_i mod n_i for all i.
  2. Because m < n_i and e = 3, m^3 < n_1 * n_2 * n_3 = N.
  3. Therefore, C = m^3 exactly over the integers without modular wrap-around.
  4. The cleartext is recovered directly via exact integer cube root: m = integer_cbrt(C).

Flag: picoCTF{1_gu3ss_p30pl3_p4d_m3ss4g3s_f0r_4_r34s0n}
Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""
import itertools
import sys
import urllib.request
from typing import Dict, List, Optional, Tuple

MSG_URL = "https://challenge-files.cylabacademy.net/picoMini+by+redpwn/Cryptography/college-rowing-team/encrypted-messages.txt"


def parse_messages(text: str) -> List[Dict[str, int]]:
    lines = text.strip().splitlines()
    entries: List[Dict[str, int]] = []
    cur: Dict[str, int] = {}
    for line in lines:
        line = line.strip()
        if not line:
            if cur:
                entries.append(cur)
                cur = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            cur[k.strip()] = int(v.strip())
    if cur:
        entries.append(cur)
    return entries


def crt(c_list: List[int], n_list: List[int]) -> Tuple[int, int]:
    N = 1
    for n in n_list:
        N *= n
    res = 0
    for c, n in zip(c_list, n_list):
        m = N // n
        inv = pow(m, -1, n)
        res = (res + c * m * inv) % N
    return res, N


def integer_cbrt(n: int) -> Optional[int]:
    lo = 1
    hi = 1 << ((n.bit_length() + 2) // 3 + 1)
    while lo <= hi:
        mid = (lo + hi) // 2
        m3 = mid**3
        if m3 == n:
            return mid
        elif m3 < n:
            lo = mid + 1
        else:
            hi = mid - 1
    return None


def solve(raw_text: Optional[str] = None) -> Optional[str]:
    content: str = ""
    if raw_text is None:
        req = urllib.request.Request(MSG_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode()
    else:
        content = raw_text

    entries = parse_messages(content)
    for combo in itertools.combinations(range(len(entries)), 3):
        c_list = [entries[i]["c"] for i in combo]
        n_list = [entries[i]["n"] for i in combo]
        C, _ = crt(c_list, n_list)
        m = integer_cbrt(C)
        if m is not None:
            msg_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
            if b"picoCTF{" in msg_bytes or b"academy{" in msg_bytes:
                return msg_bytes.decode()
    return None


if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            flag = solve(f.read())
    else:
        flag = solve()
    print("Flag:", flag)
