#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 397: GDB baby step 3 (picoCTF 2023)
Category: Reverse Engineering / x86_64 Little-Endian Memory Layout & GDB Inspection
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Dynamic Binary Instrumentation & Byte-level Memory Inspection)

Description:
`0x2262c96b` is loaded into memory in the `main` function. Examine byte-wise the
memory that the constant is loaded in by using the GDB command `x/4xb addr`.
The flag is the four bytes as they are stored in memory: academy{0x11223344}.

Disassembly of main:
0000000000401106 <main>:
  401106:	endbr64 
  40110a:	push   rbp
  40110b:	mov    rbp,rsp
  40110e:	mov    DWORD PTR [rbp-0x14],edi
  401111:	mov    QWORD PTR [rbp-0x20],rsi
  401115:	mov    DWORD PTR [rbp-0x4],0x2262c96b
  40111c:	mov    eax,DWORD PTR [rbp-0x4]
  40111f:	pop    rbp
  401120:	ret

Analysis:
The instruction `mov DWORD PTR [rbp-0x4], 0x2262c96b` stores the 32-bit dword into memory.
Because the x86-64 architecture implements Little-Endian byte ordering, the least
significant byte (LSB) is stored at the lowest physical memory address:
- [rbp-0x4] = 0x6b
- [rbp-0x3] = 0xc9
- [rbp-0x2] = 0x62
- [rbp-0x1] = 0x22
Inspecting with GDB `x/4xb $rbp-0x4` yields: `0x6b 0xc9 0x62 0x22`.
Flag: academy{0x6bc96222}
"""

import os
import re
import subprocess
import urllib.request

BINARY_URL = "https://challenge-files.cylabacademy.net/library/5eb60afe8ad6df789decfd9d5af027dc8184bfbc20e953f76ed38bd9ce3d9582/debugger0_c"
EXPECTED_FLAG = "academy{0x6bc96222}"

def solve(binary_path: str | None = None) -> str:
    # If binary path is not given, check local cache or download
    if binary_path is None or not os.path.exists(binary_path):
        cached_path = "/home/lionelsabdani36/.hermes/cache/scratch/batch63/debugger0_c"
        if os.path.exists(cached_path):
            binary_path = cached_path
        else:
            scratch_dir = "/home/lionelsabdani36/.hermes/cache/scratch/batch63"
            os.makedirs(scratch_dir, exist_ok=True)
            binary_path = os.path.join(scratch_dir, "debugger0_c")
            req = urllib.request.Request(BINARY_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                with open(binary_path, "wb") as f:
                    f.write(resp.read())
            os.chmod(binary_path, 0o755)

    assert os.path.exists(binary_path)

    # First attempt: dynamic GDB examination at breakpoint
    try:
        cmd = ["gdb", "-batch", "-ex", "break *0x40111c", "-ex", "run", "-ex", "x/4xb $rbp-0x4", binary_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        # Match hex byte pattern e.g. 0x6b\t0xc9\t0x62\t0x22
        m = re.findall(r"0x([0-9a-fA-F]{2})", proc.stdout)
        if len(m) >= 4:
            byte_hex = "".join(m[:4]).lower()
            flag = f"academy{{0x{byte_hex}}}"
            assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
            return flag
    except Exception:
        pass

    # Fallback: static disassembly analysis and little-endian byte ordering
    res = subprocess.run(["objdump", "-d", "-M", "intel", binary_path], capture_output=True, text=True, check=True)
    out = res.stdout

    m_mov = re.search(r"mov\s+DWORD PTR\s+\[rbp-0x4\],\s*(0x[0-9a-fA-F]+)", out)
    if not m_mov:
        raise ValueError("Could not find mov DWORD PTR [rbp-0x4] in disassembly")

    v_str = m_mov.group(1)
    val = int(v_str, 16)
    # Pack as 32-bit little-endian
    raw_bytes = val.to_bytes(4, byteorder="little")
    byte_hex = raw_bytes.hex().lower()
    flag = f"academy{{0x{byte_hex}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Recovered Flag: {flag}")
