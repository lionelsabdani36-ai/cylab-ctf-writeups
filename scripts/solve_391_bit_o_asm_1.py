#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 391: Bit-O-Asm-1 (picoCTF 2023)
Category: Reverse Engineering / x86_64 Assembly Tracing
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Static Binary Analysis & Assembly Tracing)

Description:
Can you figure out what is in the eax register? Put your answer in decimal:
academy{n}.

Assembly Analysis:
<+0>:     endbr64 
<+4>:     push   rbp
<+5>:     mov    rbp,rsp
<+8>:     mov    DWORD PTR [rbp-0x4],edi
<+11>:    mov    QWORD PTR [rbp-0x10],rsi
<+15>:    mov    eax,0x30
<+20>:    pop    rbp
<+21>:    ret

At <+15>, 0x30 is loaded into eax. 0x30 in base 10 = 48.
Flag: academy{48}
"""

import re
import urllib.request

DUMP_URL = "https://challenge-files.cylabacademy.net/library/f24a79de39123fb31928d2d4baf2de2385e587d089b95005083051f9afb90fa9/disassembler-dump0_a.txt"
EXPECTED_FLAG = "academy{48}"

def solve(dump_text: str | None = None) -> str:
    if dump_text is None:
        try:
            req = urllib.request.Request(DUMP_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                dump_text = resp.read().decode("utf-8")
        except Exception:
            dump_text = """<+0>:     endbr64 \n<+4>:     push   rbp\n<+5>:     mov    rbp,rsp\n<+8>:     mov    DWORD PTR [rbp-0x4],edi\n<+11>:    mov    QWORD PTR [rbp-0x10],rsi\n<+15>:    mov    eax,0x30\n<+20>:    pop    rbp\n<+21>:    ret"""

    assert dump_text is not None
    match = re.search(r"mov\s+eax,\s*(0x[0-9a-fA-F]+|[0-9]+)", dump_text)
    if not match:
        raise ValueError("Could not find mov eax instruction in dump")
    val_str = match.group(1)
    val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
    flag = f"academy{{{val}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Recovered Flag: {flag}")
