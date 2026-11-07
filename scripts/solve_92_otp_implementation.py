#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 92: OTP Implementation (picoCTF 2020)
Category: Reverse Engineering
Flag: academy{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_731cd140}
"""
def jumble(c):
    c = ord(c)
    v2 = c + 9 if c > 96 else c
    v3 = 2 * (v2 % 16)
    if v3 > 15: v3 += 1
    return v3 % 256

def solve():
    ct = "fbfgakjbjnndpippmclmnjonmilohidamgofjkmfogfceogbjehcdkpbabgneddjpnnfddpedocpjemlfejnienpedmlpboihgda"
    target_s1 = [ord(c) - 97 for c in ct]
    valid = "0123456789abcdef"
    key = ""
    for i in range(len(ct)):
        t = target_s1[i]
        prev = target_s1[i-1] if i > 0 else 0
        for cand in valid:
            jb = jumble(cand)
            comp = (jb % 16) if i == 0 else ((prev + jb) & 0xf)
            if comp == t:
                key += cand
                break
    enc_flag = bytes.fromhex("c74b3490276e15cb80bdf5dbc6f497b410264a70f78d4a793faee5d5a79fe064074b1435cc4a6e0e0095e5f0ccab10d1cf93")
    flag = bytes([e ^ k for e, k in zip(enc_flag, bytes.fromhex(key))]).decode()
    print(f"[+] Recovered flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
