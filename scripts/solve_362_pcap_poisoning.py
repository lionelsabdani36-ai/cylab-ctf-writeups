#!/usr/bin/env python3
"""Solver for Challenge 362 - PcapPoisoning (picoCTF 2023, Forensics).

The challenge provides a network packet capture file (trace.pcap).
Analysis reveals:
1. The packet capture contains TCP network traffic between endpoints.
2. In packet #507, an unencrypted TCP payload carries the plaintext flag.
3. Carving strings or regex matching on the raw pcap data directly extracts:
   academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}

Verified: academy{P64P_4N4L7S1S_SU55355FUL_7a51913b} (POST /api/submissions/ -> correct:true)
"""
import os
import re
import sys
import urllib.request

PCAP_URL = "https://challenge-files.cylabacademy.net/library/bf43414dce46c86b07479bed59c41053bc3bc9678ef4f501fbea508f14a00db3/trace.pcap"
EXPECTED_FLAG = "academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}"


def solve(pcap_path: str = "trace.pcap") -> str:
    if not os.path.exists(pcap_path):
        print(f"[*] Downloading {PCAP_URL}...")
        urllib.request.urlretrieve(PCAP_URL, pcap_path)

    with open(pcap_path, "rb") as f:
        data = f.read()

    match = re.search(rb"(?:academy|picoCTF|CTF)\{[^}]+\}", data)
    if not match:
        raise ValueError("Flag not found in PCAP trace")

    flag = match.group(0).decode("utf-8", errors="replace")
    print(f"[+] Recovered flag: {flag}")
    assert flag == EXPECTED_FLAG
    return flag


if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "/tmp/trace.pcap" if os.path.exists("/tmp/trace.pcap") else "trace.pcap")
