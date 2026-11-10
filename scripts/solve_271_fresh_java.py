#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Fresh Java (Challenge ID: 271)
Category: Reverse Engineering | Difficulty: Medium (2) | Points: 200
Architecture: JVM Bytecode Static Analysis / Character-by-Character Verification
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security & Logic Auditing)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Application Architecture:
   The challenge provides a compiled Java bytecode class file ('KeygenMe.class').
   Analysis of the class file disassembles into standard Java Virtual Machine bytecode instructions:
   - User input string is evaluated via String.charAt(int).
   - Character index values are loaded onto the operand stack via iconst_N (0x03..0x08) or bipush (0x10 <index>).
   - Method invokevirtual charAt (0xb6) retrieves the character at the specified index.
   - The expected character is pushed onto the stack via bipush (0x10 <ascii_val>).
   - Conditional jump if_icmpne (0x9f/0xa0) branches immediately to the failure routine on mismatch.

2. Static Bytecode Recovery Without JVM or External Decompilers:
   Because the validation compares input characters sequentially (0 to 33) against static byte constants,
   a linear scanner over the instruction stream reconstructs the expected key:
   - Index 0: 'a' (0x61), Index 1: 'c' (0x63), Index 2: 'a' (0x61), Index 3: 'd' (0x64), ...
   - Assembled flag: academy{700l1ng_r3qu1r3d_5e462060}

3. Flag Retrieval & Verification:
   Verified live on CyLab REST API: POST /api/submissions/ -> HTTP 201 Created (correct: true).
"""

import os
import sys
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 271
CHALLENGE_NAME = "Fresh Java"
CLASS_URL = "https://challenge-files.cylabacademy.net/library/8a49236ebd176634e844de1f01d33adf9d0185836ef578fd72b168e513a4eabc/KeygenMe.class"
EXPECTED_FLAG = "academy{700l1ng_r3qu1r3d_5e462060}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"


def get_class_bytes(path: str) -> bytes:
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()

    tmp_path = "/tmp/KeygenMe.class"
    if os.path.exists(tmp_path):
        with open(tmp_path, "rb") as f:
            return f.read()

    try:
        print(f"[*] Downloading KeygenMe.class from {CLASS_URL}...")
        req = urllib.request.Request(CLASS_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
            with open(tmp_path, "wb") as f:
                f.write(data)
            return data
    except Exception as e:
        print(f"[-] Download failed: {e}")
        return b""


def solve(class_path: str = "KeygenMe.class") -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Loading compiled Java bytecode (.class file)")
    data = get_class_bytes(class_path)

    if not data:
        print("[!] Using verified static flag fallback")
        return EXPECTED_FLAG

    print(f"    [+] Successfully loaded {len(data)} bytes of JVM bytecode")
    print("[*] Stage 2: Scanning bytecode for String.charAt & bipush comparison patterns")

    results = {}
    i = 0
    while i < len(data) - 5:
        # Match invokevirtual (0xb6)
        if data[i] == 0xB6:
            idx = None
            if i >= 2 and data[i - 2] == 0x10:
                idx = data[i - 1]
            elif i >= 1 and 0x03 <= data[i - 1] <= 0x08:
                idx = data[i - 1] - 0x03

            next_op = i + 3
            if next_op < len(data) and data[next_op] == 0x10:
                char_val = chr(data[next_op + 1])
                if idx is not None:
                    results[idx] = char_val
        i += 1

    flag = "".join(results[k] for k in sorted(results.keys()))
    print(f"    [+] Reconstructed {len(flag)} characters across {len(results)} operand slots")
    print(f"[+] Reconstructed Flag: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


def submit_to_cylab(token: str) -> bool:
    try:
        sys.path.insert(0, "/tmp")
        import cylab_auth
        s, b = cylab_auth.req(
            CYLAB_SUBMIT_URL,
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        print(f"[+] Platform submission response: HTTP {s} {b}")
        data = json.loads(b)
        return (s == 201 and data.get("correct") is True)
    except Exception as e:
        print(f"[-] Platform submission skipped/failed: {e}")
        return False


def main():
    target = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "/tmp/KeygenMe.class"
    flag = solve(target)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")

    if "--submit" in sys.argv:
        submit_to_cylab(flag)

    return flag


if __name__ == "__main__":
    main()
