#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 392: Bit-O-Asm-2 (picoCTF 2023)
Category: Reverse Engineering / x86_64 Stack Memory Tracing
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Static Binary Analysis & Pointer Dereference)

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
<+22>:    mov    eax,DWORD PTR [rbp-0x4]
<+25>:    pop    rbp
<+26>:    ret

At <+15>, 0x9fe1a is stored at stack offset [rbp-0x4].
At <+22>, the DWORD at [rbp-0x4] is moved into eax.
0x9fe1a in base 10 = 654874.
Flag: academy{654874}
"""

import re
import urllib.request

DUMP_URL = "https://challenge-files.cylabacademy.net/library/0325d59cb3b29a78bb7872b19f37856d51973b33085362dd4fe5f4cbe7aef80c/disassembler-dump0_b.txt"
EXPECTED_FLAG = "academy{654874}"

def solve(dump_text: str | None = None) -> str:
    if dump_text is None:
        try:
            req = urllib.request.Request(DUMP_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                dump_text = resp.read().decode("utf-8")
        except Exception:
            dump_text = """<+0>:     endbr64 \n<+4>:     push   rbp\n<+5>:     mov    rbp,rsp\n<+8>:     mov    DWORD PTR [rbp-0x14],edi\n<+11>:    mov    QWORD PTR [rbp-0x20],rsi\n<+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a\n<+22>:    mov    eax,DWORD PTR [rbp-0x4]\n<+25>:    pop    rbp\n<+26>:    ret"""

    assert dump_text is not None
    # Track store to stack memory
    store_match = re.search(r"mov\s+DWORD PTR\s+\[(rbp-[0-9a-fx]+)\],\s*(0x[0-9a-fA-F]+|[0-9]+)", dump_text)
    if not store_match:
        raise ValueError("Could not find store to stack in dump")
    stack_loc = store_match.group(1)
    val_str = store_match.group(2)
    val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)

    # Verify load from same stack loc to eax
    load_pattern = rf"mov\s+eax,\s*DWORD PTR\s+\[{re.escape(stack_loc)}\]"
    assert re.search(load_pattern, dump_text), f"Load from {stack_loc} into eax not found"

    flag = f"academy{{{val}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Recovered Flag: {flag}")
