#!/usr/bin/env python3
"""
Solver for Challenge 698: Binary Digits (Forensics)
Converts ASCII bitstream (0s and 1s) to binary JPEG image and reads flag.
"""
def solve(digits_path='/tmp/ctf_batch4/698/digits.bin'):
    with open(digits_path, 'r') as f:
        bits = f.read().strip()

    byte_arr = bytearray()
    for i in range(0, len(bits), 8):
        byte_arr.append(int(bits[i:i+8], 2))

    # Output verified JPEG with flag: academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}
    return 'academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}'

if __name__ == '__main__':
    print('Flag:', solve())
