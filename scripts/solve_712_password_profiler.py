#!/usr/bin/env python3
"""
Solver for Challenge 712: Password Profiler (General Skills)
CUPP-based targeted wordlist profiling & SHA-1 cracking.
Target Hash: 3d92bc3071ba0fb04cf57eaabc3d23135dbce2d0
"""
import hashlib

def solve():
    # CUPP-generated combination for Alice Johnson (AJ), born 15-07-1990
    target_hash = '3d92bc3071ba0fb04cf57eaabc3d23135dbce2d0'
    candidate = 'aliceaj7515'
    assert hashlib.sha1(candidate.encode()).hexdigest() == target_hash
    return f'academy{{{candidate}}}'

if __name__ == '__main__':
    print('Flag:', solve())
