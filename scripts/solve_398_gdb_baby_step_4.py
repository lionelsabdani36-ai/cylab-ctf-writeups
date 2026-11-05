#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 398: GDB baby step 4 (picoCTF 2023)
Category: Reverse Engineering / Function Call Tracing & Multiplication Factor Recovery
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Static Binary Disassembly & Arithmetic Opcode Analysis)

Description:
`main` calls a function that multiplies `eax` by a constant. The flag for this
challenge is that constant in decimal base: academy{n}.

Disassembly of func1:
0000000000401106 <func1>:
  401106:	endbr64 
  40110a:	push   rbp
  40110b:	mov    rbp,rsp
  40110e:	mov    DWORD PTR [rbp-0x4],edi
  401111:	mov    eax,DWORD PTR [rbp-0x4]
  401114:	69 c0 69 32 00 00    	imul   eax,eax,0x3269
  40111a:	5d                   	pop    rbp
  40111b:	c3                   	ret

Analysis:
The function `func1` receives the argument in `edi`, moves it to `eax`, and executes
`imul eax, eax, 0x3269`.
The multiplication constant is 0x3269.
In base 10 (decimal):
(3 * 16^3) + (2 * 16^2) + (6 * 16^1) + 9
= (3 * 4096) + (2 * 256) + 96 + 9
= 12288 + 512 + 96 + 9 = 12905.
Flag: academy{12905}
"""

import os
import re
import subprocess
import urllib.request

BINARY_URL = "https://challenge-files.cylabacademy.net/library/5c4fe0af7766d02123d4ebea4a32b3b461fc6c5947049092d61d47518f298068/debugger0_d"
EXPECTED_FLAG = "academy{12905}"

def solve(binary_path: str | None = None) -> str:
    # If binary path is not given, check local cache or download
    if binary_path is None or not os.path.exists(binary_path):
        cached_path = "/home/lionelsabdani36/.hermes/cache/scratch/batch63/debugger0_d"
        if os.path.exists(cached_path):
            binary_path = cached_path
        else:
            scratch_dir = "/home/lionelsabdani36/.hermes/cache/scratch/batch63"
            os.makedirs(scratch_dir, exist_ok=True)
            binary_path = os.path.join(scratch_dir, "debugger0_d")
            req = urllib.request.Request(BINARY_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                with open(binary_path, "wb") as f:
                    f.write(resp.read())
            os.chmod(binary_path, 0o755)

    assert os.path.exists(binary_path)

    # Disassemble binary using objdump
    res = subprocess.run(["objdump", "-d", "-M", "intel", binary_path], capture_output=True, text=True, check=True)
    out = res.stdout

    # Find imul eax, ... instruction in func1
    m = re.search(r"imul\s+eax,\s*eax,\s*(0x[0-9a-fA-F]+|[0-9]+)", out)
    if not m:
        raise ValueError("Could not find imul eax, eax, <constant> in disassembly")

    v_str = m.group(1)
    val = int(v_str, 16) if v_str.startswith("0x") else int(v_str)

    flag = f"academy{{{val}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Recovered Flag: {flag}")
