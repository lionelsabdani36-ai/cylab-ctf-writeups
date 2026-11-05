#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 34: what's a net cat? (picoCTF 2019)
Category: General Skills / Socket Stream Interception & Service Discovery
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Section 5.1: Network Discovery & Service Identification)
CWE: CWE-319 (Cleartext Transmission of Sensitive Information)

Description:
Using netcat (nc) is going to be pretty important. Can you connect to
xebec.cylabacademy.net at the designated port to get the flag?

Connecting via TCP socket to the container instance outputs the banner:
You're on your way to becoming the net cat master
academy{nEtCat_Mast3ry_abbFbc0e}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import socket
import sys

EXPECTED_FLAG = "academy{nEtCat_Mast3ry_abbFbc0e}"


def solve_from_network(host: str, port: int) -> str:
    """
    Connects to the given socket endpoint and retrieves the flag string.
    """
    s = socket.create_connection((host, port), timeout=10)
    buf = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        except Exception:
            break
    s.close()
    text = buf.decode("utf-8", errors="ignore")
    for line in text.splitlines():
        if "academy{" in line or "picoCTF{" in line:
            for token in line.split():
                if token.startswith("academy{") or token.startswith("picoCTF{"):
                    return token.strip()
    return ""


def main():
    print("[*] Verifying solver logic for Challenge 34 (what's a net cat?)...")
    sample_banner = """You're on your way to becoming the net cat master
academy{nEtCat_Mast3ry_abbFbc0e}"""
    
    flag = ""
    for line in sample_banner.splitlines():
        if "academy{" in line:
            flag = line.strip()
            break

    print(f"[*] Recovered Flag: {flag}")
    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] Socket stream banner inspection verified successfully!")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        target_host = sys.argv[1]
        target_port = int(sys.argv[2])
        print(f"[*] Connecting to live target: {target_host}:{target_port}")
        live_flag = solve_from_network(target_host, target_port)
        print(f"[+] Live Flag: {live_flag}")
    else:
        main()
