#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 394: Bit-O-Asm-4 (picoCTF 2023)
Category: Reverse Engineering / x86_64 Conditional Branching & Subtraction Tracing
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Static Binary Analysis & Control Flow Branch Tracing)

Description:
Can you figure out what is in the eax register? Put your answer in decimal:
academy{n}.

Assembly Analysis:
<+0>:     endbr64 
<+4>:     push   rbp
<+5>:     mov    rbp,rsp
<+8>:     mov    DWORD PTR [rbp-0x14],edi
<+11>:    mov    QWORD PTR [rbp-0x20],rsi
<+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a
<+22>:    cmp    DWORD PTR [rbp-0x4],0x2710
<+29>:    jle    0x55555555514e <main+37>
<+31>:    sub    DWORD PTR [rbp-0x4],0x65
<+35>:    jmp    0x555555555152 <main+41>
<+37>:    add    DWORD PTR [rbp-0x4],0x65
<+41>:    mov    eax,DWORD PTR [rbp-0x4]
<+44>:    pop    rbp
<+45>:    ret

Computation:
[rbp-0x4] = 0x9fe1a (654874)
Compare [rbp-0x4] with 0x2710 (10000):
654874 <= 10000 is FALSE, so jle branch at <+29> is NOT taken.
Next instruction at <+31>:
[rbp-0x4] = [rbp-0x4] - 0x65 = 654874 - 101 = 654773
Unconditional jump <+35> jmp to <+41>:
eax = [rbp-0x4] = 654773
Flag: academy{654773}
"""

import re
import urllib.request

DUMP_URL = "https://challenge-files.cylabacademy.net/library/b14a53c80d0f28fa842055ab567694917ef71b9f466545c3597aa8940284e212/disassembler-dump0_d.txt"
EXPECTED_FLAG = "academy{654773}"

def solve(dump_text: str | None = None) -> str:
    if dump_text is None:
        try:
            req = urllib.request.Request(DUMP_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                dump_text = resp.read().decode("utf-8")
        except Exception:
            dump_text = """<+0>:     endbr64 \n<+4>:     push   rbp\n<+5>:     mov    rbp,rsp\n<+8>:     mov    DWORD PTR [rbp-0x14],edi\n<+11>:    mov    QWORD PTR [rbp-0x20],rsi\n<+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a\n<+22>:    cmp    DWORD PTR [rbp-0x4],0x2710\n<+29>:    jle    0x55555555514e <main+37>\n<+31>:    sub    DWORD PTR [rbp-0x4],0x65\n<+35>:    jmp    0x555555555152 <main+41>\n<+37>:    add    DWORD PTR [rbp-0x4],0x65\n<+41>:    mov    eax,DWORD PTR [rbp-0x4]\n<+44>:    pop    rbp\n<+45>:    ret"""

    assert dump_text is not None

    # Parse and simulate basic x86 block
    val = 0
    cmp_val = 0
    sub_val = 0
    add_val = 0

    m_init = re.search(r"mov\s+DWORD PTR\s+\[rbp-0x4\],\s*(0x[0-9a-fA-F]+|[0-9]+)", dump_text)
    if m_init:
        v = m_init.group(1)
        val = int(v, 16) if v.startswith("0x") else int(v)

    m_cmp = re.search(r"cmp\s+DWORD PTR\s+\[rbp-0x4\],\s*(0x[0-9a-fA-F]+|[0-9]+)", dump_text)
    if m_cmp:
        v = m_cmp.group(1)
        cmp_val = int(v, 16) if v.startswith("0x") else int(v)

    m_sub = re.search(r"sub\s+DWORD PTR\s+\[rbp-0x4\],\s*(0x[0-9a-fA-F]+|[0-9]+)", dump_text)
    if m_sub:
        v = m_sub.group(1)
        sub_val = int(v, 16) if v.startswith("0x") else int(v)

    m_add = re.search(r"add\s+DWORD PTR\s+\[rbp-0x4\],\s*(0x[0-9a-fA-F]+|[0-9]+)", dump_text)
    if m_add:
        v = m_add.group(1)
        add_val = int(v, 16) if v.startswith("0x") else int(v)

    if val <= cmp_val:
        eax = val + add_val
    else:
        eax = val - sub_val

    flag = f"academy{{{eax}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Recovered Flag: {flag}")
