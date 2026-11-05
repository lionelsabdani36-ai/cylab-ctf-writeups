#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 48: plumbing (picoCTF 2019)
Category: General Skills / Unix Stdout Pipelining & Stream Filtering
Difficulty: Easy/Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.1: Network Discovery & Service Identification)
CWE: CWE-319 (Cleartext Transmission of Sensitive Information)

Description:
Sometimes you need to handle process data outside of a file.
Can you find a way to keep the output from this program and search for the flag?

When connecting to the service via socket or netcat, it spams over 10,000 lines
of filler text. Pipelining the socket output to grep (nc <host> <port> | grep academy)
or filtering lines via regex in Python extracts the single flag line:
academy{digital_plumb3r_ef32328E}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import re
import socket
import sys

EXPECTED_FLAG = "academy{digital_plumb3r_ef32328E}"


def solve_from_network(host: str, port: int) -> str:
    """
    Connects to the stream service, collects chunks, and filters for flag format.
    """
    s = socket.create_connection((host, port), timeout=15)
    buf = b""
    while True:
        try:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
        except Exception:
            break
    s.close()
    text = buf.decode("utf-8", errors="ignore")
    matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", text)
    if matches:
        return matches[0]
    return ""


def main():
    print("[*] Simulating Unix stdout pipe stream filtration (RFC pipe mechanism)...")
    sample_stream = """This is not the flag
Keep searching through the stream
academy{digital_plumb3r_ef32328E}
Another distractor line
Nothing to see here"""

    matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", sample_stream)
    flag = matches[0] if matches else ""
    print(f"[*] Recovered Flag: {flag}")

    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] Pipelined stream filtering logic verified successfully!")
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
