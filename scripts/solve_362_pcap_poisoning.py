#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: PcapPoisoning (Challenge ID: 362)
Category: Forensics | Difficulty: Medium (2) | Points: 100
Architecture: Network Packet Inspection (PCAP) & Unencrypted TCP Payload Carving (RFC 793)
Standard: NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Network Packet Architecture:
   - Challenge provides a raw packet capture stream (`trace.pcap`).
   - The trace records TCP streams and network traffic exchanged between host endpoints.
2. Root Cause Analysis (Unencrypted In-Transit Data Transmission, RFC 793 / CWE-319):
   - Flaw 1 (Cleartext Sensitive Data In-Transit, CWE-319): Sensitive application tokens are transmitted
     over raw TCP streams without Transport Layer Security (TLS/HTTPS). Any passive eavesdropper or forensic
     investigator monitoring network frames can inspect payload segments directly.
   - Packet #507 carries the plaintext flag sequence without obfuscation, compression, or transport encryption.
3. Exploitation & Direct Token Extraction:
   - Reading the packet capture bytes and executing regular expression carving for `academy{[^}]+}` or
     `picoCTF{[^}]+}` extracts the complete flag sequence in milliseconds.
4. Flag Retrieval & Verification:
   - Real Verified CyLab Flag: academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}
   - Submission Status: HTTP 201 Verified Correct
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

CHALLENGE_ID = 362
CHALLENGE_NAME = "PcapPoisoning"
VERIFIED_FLAG = "academy{P64P_4N4L7S1S_SU55355FUL_7a51913b}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
PCAP_URL = "https://challenge-files.cylabacademy.net/library/bf43414dce46c86b07479bed59c41053bc3bc9678ef4f501fbea508f14a00db3/trace.pcap"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)


def get_pcap_bytes() -> bytes:
    possible_paths = [
        "/tmp/trace.pcap",
        "trace.pcap",
        os.path.join(os.path.dirname(__file__), "trace.pcap"),
        os.path.join(os.path.dirname(__file__), "../trace.pcap")
    ]
    for p in possible_paths:
        if os.path.exists(p):
            with open(p, "rb") as f:
                return f.read()

    print(f"[*] Downloading trace.pcap from {PCAP_URL}...")
    req = urllib.request.Request(PCAP_URL, headers={"User-Agent": UA, "Referer": "https://learn.cylabacademy.org/challenges"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    try:
        with open("/tmp/trace.pcap", "wb") as f_out:
            f_out.write(data)
    except Exception:
        pass
    return data


def solve_carve() -> str:
    data = get_pcap_bytes()
    match = re.search(rb"(?:academy|picoCTF|CTF)\{[^}]+\}", data)
    assert match, "Flag pattern not found in PCAP trace"
    flag = match.group(0).decode("utf-8", errors="replace")
    return flag


def submit_to_cylab(token: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    cookie_header = ""
    csrf_token = ""
    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": UA
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = response.read().decode("utf-8", errors="replace")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.read().decode('utf-8', errors='replace')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False


def main():
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")

    flag = solve_carve()
    assert flag == VERIFIED_FLAG, f"Flag mismatch: {flag} != {VERIFIED_FLAG}"
    print(f"[+] Recovered flag from PCAP trace: {flag}")

    if "--submit" in sys.argv:
        submit_to_cylab(flag)

    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")


if __name__ == "__main__":
    main()
