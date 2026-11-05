#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 396: GDB baby step 2 (picoCTF 2023)
Category: Reverse Engineering / x86_64 Dynamic Analysis & Loop Tracing
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Dynamic Binary Instrumentation & GDB Breakpoint Inspection)

Description:
Can you figure out what is in the eax register at the end of the main function?
Put your answer in the academy flag format: academy{n} where n is the contents
of the eax register in the decimal number base.

Disassembly of main:
0000000000401106 <main>:
  401106:	endbr64 
  40110a:	push   rbp
  40110b:	mov    rbp,rsp
  40110e:	mov    DWORD PTR [rbp-0x14],edi
  401111:	mov    QWORD PTR [rbp-0x20],rsi
  401115:	mov    DWORD PTR [rbp-0x4],0x1e0da
  40111c:	mov    DWORD PTR [rbp-0xc],0x25f
  401123:	mov    DWORD PTR [rbp-0x8],0x0
  40112a:	jmp    401136 <main+0x30>
  40112c:	mov    eax,DWORD PTR [rbp-0x8]
  40112f:	add    DWORD PTR [rbp-0x4],eax
  401132:	add    DWORD PTR [rbp-0x8],0x1
  401136:	mov    eax,DWORD PTR [rbp-0x8]
  401139:	cmp    eax,DWORD PTR [rbp-0xc]
  40113c:	jl     40112c <main+0x26>
  40113e:	mov    eax,DWORD PTR [rbp-0x4]
  401141:	pop    rbp
  401142:	ret

Loop Simulation:
[rbp-0x4] (accumulator) = 0x1e0da (123098)
[rbp-0xc] (limit) = 0x25f (607)
[rbp-0x8] (counter i) = 0
While i < 607:
    accumulator += i
    i += 1
Sum of i from 0 to 606 = (606 * 607) / 2 = 183921.
Wait:
123098 + 183921 = 307019.
Final eax = 307019.
Flag: academy{307019}
"""

import os
import re
import subprocess
import urllib.request

BINARY_URL = "https://challenge-files.cylabacademy.net/library/eea5e81c4ce7d6dcb85a3fe7d2edae4465705d230c68c45365cb9f24a69dfcf1/debugger0_b"
EXPECTED_FLAG = "academy{307019}"

def solve(binary_path: str | None = None) -> str:
    # If binary path is not given, check local cache or download
    if binary_path is None or not os.path.exists(binary_path):
        cached_path = "/home/lionelsabdani36/.hermes/cache/scratch/batch62/debugger0_b"
        if os.path.exists(cached_path):
            binary_path = cached_path
        else:
            scratch_dir = "/home/lionelsabdani36/.hermes/cache/scratch/batch62"
            os.makedirs(scratch_dir, exist_ok=True)
            binary_path = os.path.join(scratch_dir, "debugger0_b")
            req = urllib.request.Request(BINARY_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                with open(binary_path, "wb") as f:
                    f.write(resp.read())
            os.chmod(binary_path, 0o755)

    assert os.path.exists(binary_path)

    # First attempt: dynamic GDB evaluation
    try:
        cmd = ["gdb", "-batch", "-ex", "break *0x401141", "-ex", "run", "-ex", "info registers eax", binary_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        m = re.search(r"eax\s+0x[0-9a-fA-F]+\s+([0-9]+)", proc.stdout)
        if m:
            val = int(m.group(1))
            flag = f"academy{{{val}}}"
            assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
            return flag
    except Exception:
        pass

    # Fallback: static disassembly analysis and loop simulation
    res = subprocess.run(["objdump", "-d", "-M", "intel", binary_path], capture_output=True, text=True, check=True)
    out = res.stdout

    m_init = re.search(r"mov\s+DWORD PTR\s+\[rbp-0x4\],\s*(0x[0-9a-fA-F]+|[0-9]+)", out)
    m_lim = re.search(r"mov\s+DWORD PTR\s+\[rbp-0xc\],\s*(0x[0-9a-fA-F]+|[0-9]+)", out)

    if not m_init or not m_lim:
        raise ValueError("Could not parse loop parameters from objdump")

    v_init = m_init.group(1)
    init_val = int(v_init, 16) if v_init.startswith("0x") else int(v_init)

    v_lim = m_lim.group(1)
    limit_val = int(v_lim, 16) if v_lim.startswith("0x") else int(v_lim)

    acc = init_val
    for i in range(limit_val):
        acc = (acc + i) & 0xFFFFFFFF

    flag = f"academy{{{acc}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Recovered Flag: {flag}")
