#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 395: GDB baby step 1 (picoCTF 2023)
Category: Reverse Engineering / x86_64 ELF Binary Disassembly & GDB Analysis
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Static Binary Disassembly & Symbol Resolution)

Description:
Can you figure out what is in the eax register at the end of the main function?
Put your answer in the academy flag format: academy{n} where n is the contents
of the eax register in the decimal number base.

Disassembly of main:
0000000000001129 <main>:
    1129:	endbr64 
    112d:	push   rbp
    112e:	mov    rbp,rsp
    1131:	mov    DWORD PTR [rbp-0x4],edi
    1134:	mov    QWORD PTR [rbp-0x10],rsi
    1138:	mov    eax,0x86342
    113d:	pop    rbp
    113e:	ret

Analysis:
The main function directly loads the constant 0x86342 into eax before returning.
0x86342 in base 10:
(8 * 16^4) + (6 * 16^3) + (3 * 16^2) + (4 * 16^1) + 2
= 524288 + 24576 + 768 + 64 + 2 = 549698.
Flag: academy{549698}
"""

import os
import re
import subprocess
import urllib.request

BINARY_URL = "https://challenge-files.cylabacademy.net/library/03b038548e2a34973bde05a78fadc1f09467a1d03ffbfb9e4b48bd44e87c0e70/debugger0_a"
EXPECTED_FLAG = "academy{549698}"

def solve(binary_path: str | None = None) -> str:
    # If binary path is not given, check local cache or download
    if binary_path is None or not os.path.exists(binary_path):
        cached_path = "/home/lionelsabdani36/.hermes/cache/scratch/batch62/debugger0_a"
        if os.path.exists(cached_path):
            binary_path = cached_path
        else:
            scratch_dir = "/home/lionelsabdani36/.hermes/cache/scratch/batch62"
            os.makedirs(scratch_dir, exist_ok=True)
            binary_path = os.path.join(scratch_dir, "debugger0_a")
            req = urllib.request.Request(BINARY_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                with open(binary_path, "wb") as f:
                    f.write(resp.read())
            os.chmod(binary_path, 0o755)

    assert os.path.exists(binary_path)

    # Disassemble main using objdump
    res = subprocess.run(["objdump", "-d", "-M", "intel", binary_path], capture_output=True, text=True, check=True)
    out = res.stdout

    m = re.search(r"mov\s+eax,\s*(0x[0-9a-fA-F]+|[0-9]+)", out)
    if not m:
        raise ValueError("Could not find mov eax in disassembly")

    v_str = m.group(1)
    val = int(v_str, 16) if v_str.startswith("0x") else int(v_str)

    flag = f"academy{{{val}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Recovered Flag: {flag}")
