#!/usr/bin/env python3
"""
Solver for Challenge 188: Mini RSA (Module 139, LP 17)
CyLab Security Academy / picoCTF 2021
Vulnerability: Low Public Exponent (e = 3) where M^3 < N (Unpadded or insufficient padding)
"""
import urllib.request
import sys

def integer_cube_root(n):
    low = 1 << ((n.bit_length() - 1) // 3)
    high = 1 << ((n.bit_length() + 2) // 3)
    while low <= high:
        mid = (low + high) // 2
        m3 = mid ** 3
        if m3 == n:
            return mid, True
        elif m3 < n:
            low = mid + 1
        else:
            high = mid - 1
    return high, False

def solve():
    url = "https://challenge-files.cylabacademy.net/library/c38aad598cec5f49f44a9d3d52f971d09b1c834876274d278c5bfef04935fceb/values"
    content = urllib.request.urlopen(url).read().decode()
    lines = content.strip().splitlines()
    N = int(lines[0].split(':')[1].strip())
    e = int(lines[1].split(':')[1].strip())
    c = int(lines[3].split(':')[1].strip())

    for k in range(0, 1000):
        val = c + k * N
        m, exact = integer_cube_root(val)
        if exact:
            raw_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            flag = raw_bytes.decode('utf-8', errors='ignore').strip()
            print("Flag:", flag)
            return flag

if __name__ == "__main__":
    solve()
