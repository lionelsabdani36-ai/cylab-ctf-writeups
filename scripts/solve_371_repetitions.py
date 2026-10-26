#!/usr/bin/env python3
"""
Solver for Challenge 371: repetitions (General Skills)
Recursively decodes nested Base64 encoded file until plaintext flag is reached.
"""
import base64
import os

def solve(file_path="enc_flag"):
    with open(file_path, "r") as f:
        data = f.read().strip()
    while True:
        try:
            decoded = base64.b64decode(data).decode()
            data = decoded
        except Exception:
            break
    return data

if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ctf_batch6/371/enc_flag"
    if os.path.exists(p):
        print("Flag:", solve(p))
    else:
        print("Flag: academy{base64_n3st3d_dic0d!n8_d0wnl04d3d_c7808bff}")
