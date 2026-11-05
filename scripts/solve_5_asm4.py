#!/usr/bin/env python3
"""
Solver for Challenge 5: asm4 (Reverse Engineering)
Simulates x86 string processing and telescoping mathematical progression for asm4("academy_0a649").
"""

def asm4(s: str) -> int:
    """
    Simulation of asm4 x86 routine:
      1. Determines string length N = strlen(s).
      2. Initializes accumulator val = 0x236.
      3. Loops index i from 1 to N - 2:
           val += (s[i] - s[i-1]) + (s[i+1] - s[i])
         Notice the interior terms cancel (telescoping sum):
           delta = s[i+1] - s[i-1]
         Total delta over all iterations simplifies to:
           (s[N-1] + s[N-2]) - (s[1] + s[0])
    """
    val = 0x236
    n = len(s)
    
    # Step-by-step assembly trace simulation:
    for i in range(1, n - 1):
        diff1 = ord(s[i]) - ord(s[i - 1])
        diff2 = ord(s[i + 1]) - ord(s[i])
        val = (val + diff1 + diff2) & 0xffffffff
        
    return val

def solve(s: str = "academy_0a649") -> str:
    ans = asm4(s)
    return f"0x{ans:x}"

if __name__ == "__main__":
    flag = solve()
    print("Flag:", flag)
