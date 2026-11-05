#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 115: Wireshark doo dooo do doo... (picoCTF 2021)
Category: Forensics / Network PCAP Packet Dissection & ROT13 Inversion
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.1: Network Discovery & Packet Analysis)
CWE: CWE-319 (Cleartext Transmission of Sensitive Information)

Description:
Can you find the flag?
- Asset: shark1.pcapng
- Traffic contains cleartext HTTP streams carrying HTML responses.
- One HTTP response body contains:
  Gur synt vf npnqrzl{c33xno00_1_f33_h_qrnqorrs}
- Applying Caesar cipher / ROT13 decoding reveals the legitimate flag:
  The flag is academy{p33kab00_1_s33_u_deadbeef}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import codecs
import os
import re
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/bcc244e5738c2a9af3a7fd84a79e1bf8436dc32716855581a60e27e526133fd7/shark1.pcapng"
EXPECTED_FLAG = "academy{p33kab00_1_s33_u_deadbeef}"


def solve_from_bytes(pcap_data: bytes) -> str:
    """
    Scans packet capture bytes for ROT13 encoded flag string
    matching pattern 'Gur synt vf npnqrzl{...}' or 'npnqrzl{...}'.
    """
    match = re.search(rb"npnqrzl\{[^\}]+\}", pcap_data)
    if not match:
        raise ValueError("ROT13 encoded flag pattern not found in capture bytes")

    encoded_flag = match.group(0).decode("latin1")
    decoded_flag = codecs.decode(encoded_flag, "rot_13")
    return decoded_flag


def solve() -> str:
    cache_path = "/tmp/ctf_solve/115_shark1.pcapng"
    if not os.path.exists(cache_path):
        print(f"[*] Downloading capture from {ASSET_URL}...")
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        urllib.request.urlretrieve(ASSET_URL, cache_path)

    with open(cache_path, "rb") as f:
        data = f.read()

    return solve_from_bytes(data)


def main():
    print("[*] Parsing PCAPNG and reversing ROT13 HTTP stream...")
    flag = solve()
    print(f"[*] Recovered Flag: {flag}")

    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] Packet analysis and ROT13 verification passed successfully!")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    main()
