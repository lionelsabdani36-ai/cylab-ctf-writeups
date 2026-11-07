#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 102: Let's get dynamic (picoCTF 2021)
Category: Reverse Engineering
Flag: academy{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_0c8f18c}
"""
import struct

def solve():
    vals_a = [166649011824203166, 2246226443284637900, 5443368435603081563, 6634115839532674854, -6741273775118318351 & 0xffffffffffffffff, 5353993955195766119]
    buf_a = b''.join(struct.pack('<Q', v) for v in vals_a)
    vals_b = [7871294989769368812, 6652410930181606323, 1224009049906308460, 2463296711132796444, -3950945058866805859 & 0xffffffffffffffff, 798037826989530220]
    buf_b = b''.join(struct.pack('<Q', v) for v in vals_b)
    flag = bytes([i ^ buf_a[i] ^ buf_b[i] ^ 19 for i in range(len(buf_a))]).decode()
    print(f"[+] Recovered flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
