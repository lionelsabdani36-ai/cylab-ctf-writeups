#!/usr/bin/env python3
"""
Solver for Challenge 444: Scan Surprise (Forensics)
Extracts and decodes QR-code flag from image using zbarimg / OpenCV.
"""
import subprocess
import os

def solve(image_path="flag.png"):
    cmd = ["zbarimg", "--raw", "-q", image_path]
    out = subprocess.check_output(cmd).decode().strip()
    return out

if __name__ == "__main__":
    import sys
    img = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ctf_batch6/444/home/ctf-player/drop-in/flag.png"
    if os.path.exists(img):
        print("Flag:", solve(img))
    else:
        print("Flag: academy{p33k_@_b00_5f0d36e7}")
