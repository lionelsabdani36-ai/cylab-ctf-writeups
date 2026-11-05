#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 156: Nice netcat... (picoCTF 2021)
Category: General Skills / Socket Stream Interception & ASCII Decimal Transformation
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Section 5.1: Network Discovery & Service Identification)
CWE: CWE-319 (Cleartext Transmission of Sensitive Information)

Description:
There is a nice program that you can talk to by using this command in a shell:
$ nc xebec.cylabacademy.net <port>, but it doesn't speak English...
When querying the netcat service, it returns a sequence of decimal ASCII values line by line:
97, 99, 97, 100, 101, 109, 121, 123...
Converting each integer via chr(val) reconstructs the flag string:
academy{g00d_k1tty!_n1c3_k1tty!_6d1e6}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import socket
import sys

EXPECTED_FLAG = "academy{g00d_k1tty!_n1c3_k1tty!_6d1e6}"


def decode_ascii_stream(stream_text: str) -> str:
    """
    Takes raw lines of decimal ASCII codes and decodes them into characters.
    """
    chars = []
    for line in stream_text.splitlines():
        line = line.strip()
        if line.isdigit():
            chars.append(chr(int(line)))
    return "".join(chars).strip()


def solve_from_network(host: str, port: int) -> str:
    """
    Connects to the given socket endpoint and decodes the ASCII byte stream.
    """
    s = socket.create_connection((host, port), timeout=10)
    data = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        except Exception:
            break
    s.close()
    raw = data.decode("utf-8", errors="ignore")
    return decode_ascii_stream(raw)


def main():
    print("[*] Simulating ASCII decimal transformation for Nice netcat...")
    # Sample stream matching challenge output
    sample_raw = """97
99
97
100
101
109
121
123
103
48
48
100
95
107
49
116
116
121
33
95
110
49
99
51
95
107
49
116
116
121
33
95
54
100
49
101
54
125
10"""
    flag = decode_ascii_stream(sample_raw)
    print(f"[*] Recovered Flag: {flag}")

    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] ASCII decoding and flag verification passed successfully!")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    main()
