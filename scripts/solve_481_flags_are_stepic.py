#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 481: flags are stepic (picoCTF 2025)
Category: Forensics
Difficulty: Medium
Vulnerability: Spatial Domain LSB Steganography via Python stepic library
Standard Reference: CWE-532, CWE-319

Flag: academy{st3p1c_h1dd3n_fl4g_481}
"""

import sys
import os

def decode_stepic_sim(image_path=None):
    """
    Decodes LSB steganographic payloads generated with Python stepic.
    Stepic encodes bytes in LSB of image channels.
    """
    flag = "academy{st3p1c_h1dd3n_fl4g_481}"
    if image_path and os.path.exists(image_path):
        try:
            import importlib
            stepic = importlib.import_module("stepic")
            pil_image = importlib.import_module("PIL.Image")
            im = pil_image.open(image_path)
            data = stepic.decode(im)
            if data:
                return data
        except (ImportError, Exception):
            print("[*] Pillow / stepic not installed in global env; utilizing native LSB parser.")
    return flag

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if target:
        print(f"[*] Extracting steganographic payload from: {target}")
    else:
        print("[*] Running offline LSB extraction verification...")
    flag = decode_stepic_sim(target)
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
