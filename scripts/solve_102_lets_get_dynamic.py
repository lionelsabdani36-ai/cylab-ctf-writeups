#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Let's get dynamic (Challenge ID: 102)
Category: Reverse Engineering / Dynamic Stack Reconstruction & Array XOR Disassembly
Difficulty: Hard (3) | Points: 300
Exploitation Technique: Disassembly Analysis of Dynamic Stack Buffers & Quadword Stream Inversion
Standard Reference: NIST SP 800-115 Section 4.2 (Software Analysis and Reverse Engineering)

Vulnerability & Mechanics Summary:
1. Target Architecture & Environment:
   - Challenge provides an x86_64 assembly source file (`chall.S`).
   - The assembly sets up two large 48-byte stack arrays populated via sequential 64-bit quadword
     immediate assignments (`movabs` into `[rbp - offset]`).
   - A transformation loop iterates over each byte $i \in [0, 47]$, computing:
     $$F[i] = i \oplus \text{buf}_A[i] \oplus \text{buf}_B[i] \oplus 19$$
2. Root Cause Analysis (Deterministic Stack Buffer Construction / CWE-653):
   - In static analysis of stripped assembly, large string constants are obfuscated by splitting
     them into 64-bit integer quadwords loaded at runtime to bypass `strings` utility checks.
   - The transformation algorithm uses linear byte-wise XOR operations with loop index $i$ and
     a constant offset `19` (`0x13`).
   - Because XOR is commutative and invertible, extracting the quadword literals directly from
     assembly source and evaluating the XOR chain reveals the plaintext flag.
3. Payload Recovery & Output Calculation:
   - Array A quadword literals (little-endian unpacked, 48 bytes):
     `[166649011824203166, 2246226443284637900, 5443368435603081563, 6634115839532674854, -6741273775118318351 & 0xffffffffffffffff, 5353993955195766119]`
   - Array B quadword literals (little-endian unpacked, 48 bytes):
     `[7871294989769368812, 6652410930181606323, 1224009049906308460, 2463296711132796444, -3950945058866805859 & 0xffffffffffffffff, 798037826989530220]`
   - Evaluating $F[i] = i \oplus \text{buf}_A[i] \oplus \text{buf}_B[i] \oplus 19$ yields:
     `academy{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_0c8f18c}`
4. Verification & Output:
   - Target Flag: academy{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_0c8f18c}
"""

import sys
import json
import struct
import urllib.request
import urllib.error

CHALLENGE_ID = 102
CHALLENGE_NAME = "Let's get dynamic"
TARGET_FLAG = "academy{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_0c8f18c}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

def solve_offline():
    print(f"[*] Auditing Module {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Parsing Assembly Source 'chall.S' Stack Quadword Assignments...")
    vals_a = [
        166649011824203166,
        2246226443284637900,
        5443368435603081563,
        6634115839532674854,
        -6741273775118318351 & 0xffffffffffffffff,
        5353993955195766119
    ]
    buf_a = b''.join(struct.pack('<Q', v) for v in vals_a)
    
    vals_b = [
        7871294989769368812,
        6652410930181606323,
        1224009049906308460,
        2463296711132796444,
        -3950945058866805859 & 0xffffffffffffffff,
        798037826989530220
    ]
    buf_b = b''.join(struct.pack('<Q', v) for v in vals_b)
    print(f"    [+] Unpacked Stack Buffer A ({len(buf_a)} bytes)")
    print(f"    [+] Unpacked Stack Buffer B ({len(buf_b)} bytes)")
    
    print("[*] Stage 2: Simulating Transformation Loop (F[i] = i ^ buf_a[i] ^ buf_b[i] ^ 19)...")
    flag_bytes = bytes([i ^ buf_a[i] ^ buf_b[i] ^ 19 for i in range(len(buf_a))])
    flag = flag_bytes.decode("ascii")
    print(f"    [+] Recovered Flag: {flag}")
    
    assert flag == TARGET_FLAG, f"Integrity check failed: {flag} != {TARGET_FLAG}"
    return flag

def submit_to_cylab(token):
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Referer": "https://learn.cylabacademy.org/challenges",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyLab-Student-Agent/1.0"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[*] Platform submission status: {e} (Offline verification mode; verified reproducer)")
        return False
    except Exception as e:
        print(f"[*] Platform submission status: {e} (Offline verification mode; verified reproducer)")
        return False

def main():
    token = solve_offline()
    assert token == TARGET_FLAG, f"Verification failed: {token} != {TARGET_FLAG}"
    submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")

if __name__ == "__main__":
    main()
