#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: Virtual Machine 0 (ID: 385)
Category: Reverse Engineering / Mechanical Gear Ratio & Byte Serialization
Event: picoCTF 2023
Difficulty: Medium (100 pts)

Analysis & Recovery:
1. Challenge provides a COLLADA 3D model (Virtual-Machine-0.dae) and input.txt.
2. The mechanical gear assembly couples an input axle (red) with an output axle (blue).
3. Analyzing the gear teeth counts in the model:
   - Red gear: 40 teeth
   - Driving gear / pinion on blue axle: 8 teeth
   - Gear transmission ratio: 40 / 8 = 5:1
4. Each single full revolution of the red axle produces 5 full revolutions of the blue axle.
5. Given the integer value in input.txt:
   output = input * 5
6. Converting the output integer to hexadecimal representation and interpreting the hex bytes
   as ASCII text recovers the complete flag: academy{g34r5_0f_m0r3_c95d6542}.
"""

import os
import sys
import urllib.request
import re

INPUT_URL = "https://challenge-files.cylabacademy.net/library/31a032462b68e74a4a4a303cccc1007b33149f2b232bec2c2c2a0840f3fbb3f1/input.txt"
STATIC_INPUT = 34414012771923267025329027534276989288205997301964262080788052262850398745
GEAR_RATIO = 5

def solve(input_path: str = "") -> str:
    val = None
    if input_path and os.path.exists(input_path):
        with open(input_path, "r") as f:
            val = int(f.read().strip())
    else:
        work_dir = os.path.join(os.environ.get("TMPDIR", "/home/lionelsabdani36/.hermes/cache/scratch"), "solve_385")
        os.makedirs(work_dir, exist_ok=True)
        cached_input = os.path.join(work_dir, "input.txt")
        if os.path.exists(cached_input):
            with open(cached_input, "r") as f:
                val = int(f.read().strip())
        else:
            try:
                print(f"[*] Downloading {INPUT_URL}...")
                urllib.request.urlretrieve(INPUT_URL, cached_input)
                with open(cached_input, "r") as f:
                    val = int(f.read().strip())
            except Exception as e:
                print(f"[*] Network fetch fallback to static constant: {e}")
                val = STATIC_INPUT

    print(f"[*] Input rotation value: {val}")
    print(f"[*] Applying mechanical gear multiplication ratio ({GEAR_RATIO}x)...")
    output_val = val * GEAR_RATIO

    hex_str = hex(output_val)[2:]
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str

    raw_bytes = bytes.fromhex(hex_str)
    decoded = raw_bytes.decode("latin-1", "replace")
    print(f"[*] Decoded raw string: {decoded}")

    m = re.search(r"(?:academy|picoCTF|CTF)\{[^}]+\}", decoded)
    if not m:
        raise RuntimeError(f"Flag not found in decoded bytes: {decoded}")

    flag = m.group(0)
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"Recovered Flag: {flag}")
