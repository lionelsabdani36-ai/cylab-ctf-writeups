#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 122: Easy as GDB (picoCTF 2021)
Category: Reverse Engineering
Flag: academy{I_5D3_A11DA7_f73c8ead}
"""
def swap_step(buf, length, step):
    i = 0
    while i < length - step + 1:
        buf[i], buf[i + step - 1] = buf[i + step - 1], buf[i]
        i += step

def permute(buf, length, mode):
    if mode > 0:
        for step in range(1, length):
            swap_step(buf, length, step)
    else:
        for step in range(length - 1, 0, -1):
            swap_step(buf, length, step)

def solve():
    target = bytes.fromhex("7a3f64633b5a167c6d436f36666246144361423f58015834623d6a303a17")
    buf = list(target)
    permute(buf, 30, -1)
    xor_key = [0x5e, 0x07, 0x23, 0x07]
    flag = bytes([buf[i] ^ xor_key[i % 4] for i in range(30)]).decode()
    print(f"[+] Recovered flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
