#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 393: Bit-O-Asm-3 (picoCTF 2023)
Category: Reverse Engineering / x86_64 Arithmetic & Register Tracing
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Static Binary Analysis & Multi-Instruction Tracing)

Description:
Can you figure out what is in the eax register? Put your answer in decimal:
academy{n}.

Assembly Analysis:
<+0>:     endbr64 
<+4>:     push   rbp
<+5>:     mov    rbp,rsp
<+8>:     mov    DWORD PTR [rbp-0x14],edi
<+11>:    mov    QWORD PTR [rbp-0x20],rsi
<+15>:    mov    DWORD PTR [rbp-0xc],0x9fe1a
<+22>:    mov    DWORD PTR [rbp-0x8],0x4
<+29>:    mov    eax,DWORD PTR [rbp-0xc]
<+32>:    imul   eax,DWORD PTR [rbp-0x8]
<+36>:    add    eax,0x1f5
<+41>:    mov    DWORD PTR [rbp-0x4],eax
<+44>:    mov    eax,DWORD PTR [rbp-0x4]
<+47>:    pop    rbp
<+48>:    ret

Computation:
[rbp-0xc] = 0x9fe1a (654874)
[rbp-0x8] = 0x4 (4)
eax = [rbp-0xc] = 654874
eax = eax * [rbp-0x8] = 654874 * 4 = 2619496
eax = eax + 0x1f5 = 2619496 + 501 = 2619997
[rbp-0x4] = eax = 2619997
eax = [rbp-0x4] = 2619997
Flag: academy{2619997}
"""

import re
import urllib.request

DUMP_URL = "https://challenge-files.cylabacademy.net/library/f16508f6e8ba4c520e7541081aee169bf4f5cab84d6852b697299b8cf4aff76a/disassembler-dump0_c.txt"
EXPECTED_FLAG = "academy{2619997}"

def solve(dump_text: str | None = None) -> str:
    if dump_text is None:
        try:
            req = urllib.request.Request(DUMP_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                dump_text = resp.read().decode("utf-8")
        except Exception:
            dump_text = """<+0>:     endbr64 \n<+4>:     push   rbp\n<+5>:     mov    rbp,rsp\n<+8>:     mov    DWORD PTR [rbp-0x14],edi\n<+11>:    mov    QWORD PTR [rbp-0x20],rsi\n<+15>:    mov    DWORD PTR [rbp-0xc],0x9fe1a\n<+22>:    mov    DWORD PTR [rbp-0x8],0x4\n<+29>:    mov    eax,DWORD PTR [rbp-0xc]\n<+32>:    imul   eax,DWORD PTR [rbp-0x8]\n<+36>:    add    eax,0x1f5\n<+41>:    mov    DWORD PTR [rbp-0x4],eax\n<+44>:    mov    eax,DWORD PTR [rbp-0x4]\n<+47>:    pop    rbp\n<+48>:    ret"""

    assert dump_text is not None
    # Parse memory map and simulate execution
    stack = {}
    eax = 0

    for line in dump_text.strip().splitlines():
        line = line.strip()
        # mov DWORD PTR [rbp-offset], immediate
        m = re.search(r"mov\s+DWORD PTR\s+\[(rbp-[0-9a-fx]+)\],\s*(0x[0-9a-fA-F]+|[0-9]+)", line)
        if m:
            loc = m.group(1)
            v = int(m.group(2), 16) if m.group(2).startswith("0x") else int(m.group(2))
            stack[loc] = v
            continue

        # mov eax, DWORD PTR [rbp-offset]
        m = re.search(r"mov\s+eax,\s*DWORD PTR\s+\[(rbp-[0-9a-fx]+)\]", line)
        if m:
            loc = m.group(1)
            eax = stack.get(loc, 0)
            continue

        # imul eax, DWORD PTR [rbp-offset]
        m = re.search(r"imul\s+eax,\s*DWORD PTR\s+\[(rbp-[0-9a-fx]+)\]", line)
        if m:
            loc = m.group(1)
            eax = (eax * stack.get(loc, 0)) & 0xFFFFFFFF
            continue

        # add eax, immediate
        m = re.search(r"add\s+eax,\s*(0x[0-9a-fA-F]+|[0-9]+)", line)
        if m:
            v = int(m.group(1), 16) if m.group(1).startswith("0x") else int(m.group(1))
            eax = (eax + v) & 0xFFFFFFFF
            continue

        # mov DWORD PTR [rbp-offset], eax
        m = re.search(r"mov\s+DWORD PTR\s+\[(rbp-[0-9a-fx]+)\],\s*eax", line)
        if m:
            loc = m.group(1)
            stack[loc] = eax
            continue

    flag = f"academy{{{eax}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Recovered Flag: {flag}")
