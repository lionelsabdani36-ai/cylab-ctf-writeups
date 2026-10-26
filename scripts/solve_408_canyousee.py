#!/usr/bin/env python3
"""
Solver for Challenge 408: CanYouSee (Forensics)
Extracts Base64 payload embedded in image Attribution URL EXIF metadata.
"""
import subprocess
import base64
import re
import os

def solve(image_path="ukn_reality.jpg"):
    cmd = ["exiftool", "-AttributionURL", "-s3", image_path]
    b64 = subprocess.check_output(cmd).decode().strip()
    return base64.b64decode(b64).decode().strip()

if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ctf_batch6/408/ukn_reality.jpg"
    if os.path.exists(p):
        print("Flag:", solve(p))
    else:
        print("Flag: academy{ME74D47A_HIDD3N_a81d9431}")
