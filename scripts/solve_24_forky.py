#!/usr/bin/env python3
"""
Solver for Challenge 24: Forky (Reverse Engineering)
Simulates x86 IPC process branching via fork() and MAP_SHARED memory accumulation.
Platform: CyLab Security Academy / picoCTF 2019
"""
import ctypes

def solve() -> str:
    """
    Simulation of Forky binary logic:
    1. mmap() allocates a 4-byte shared anonymous memory region (MAP_SHARED | MAP_ANONYMOUS).
    2. Shared integer initialized to 0x3b9aca00 (1,000,000,000 decimal).
    3. Binary invokes fork() 4 times consecutively:
       - 2^4 = 16 concurrent processes are created.
    4. Each process reads the shared integer, adds 0x499602d2 (1,234,567,890 decimal),
       and writes it back to the shared memory.
    5. The final process passes this mutated 32-bit signed integer to doNothing().
    """
    initial_val = 0x3b9aca00  # 1,000,000,000
    increment = 0x499602d2    # 1,234,567,890
    num_forks = 4
    num_processes = 2 ** num_forks  # 16 processes
    
    # Cumulative addition across all 16 processes on shared memory
    total_acc = (initial_val + num_processes * increment) & 0xffffffff
    
    # Cast to 32-bit signed integer representation as passed in register EAX
    signed_val = ctypes.c_int32(total_acc).value
    
    return f"academy{{{signed_val}}}"

if __name__ == "__main__":
    flag = solve()
    print("Flag:", flag)
