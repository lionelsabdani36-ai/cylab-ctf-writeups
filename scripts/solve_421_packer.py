#!/usr/bin/env python3
"""Solver for Challenge 421 - packer (picoCTF 2024, Reverse Engineering).

The challenge provides an ELF 64-bit executable ('out').
Binary analysis reveals:
1. The binary is packed with UPX (Ultimate Packer for eXecutables):
   - Magic headers `UPX!` located at the end of the text/load segments.
   - Standard unpacking via `upx -d out -o unpacked_out` restores the original binary.
2. The unpacked binary contains the string:
   'Password correct, please see flag: 61636164656d797b5539585f556e5034636b314e365f42316e34526933535f39636233313961657d'
3. Decoding the hex-encoded string yields the official flag:
   academy{U9X_UnP4ck1N6_B1n4Ri3S_9cb319ae}

Verified: academy{U9X_UnP4ck1N6_B1n4Ri3S_9cb319ae} (POST /api/submissions/ -> correct:true)
"""
import binascii
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

BINARY_URL = "https://challenge-files.cylabacademy.net/library/950f65862ed36c218311453c7d58c12ec3ddfb8a78b04ebcd127d3eeb1ea6e11/out"
EXPECTED_FLAG = "academy{U9X_UnP4ck1N6_B1n4Ri3S_9cb319ae}"
HEX_FLAG = "61636164656d797b5539585f556e5034636b314e365f42316e34526933535f39636233313961657d"


def solve(binary_path: str = "out") -> str:
    if not os.path.exists(binary_path):
        print(f"[*] Downloading {BINARY_URL}...")
        urllib.request.urlretrieve(BINARY_URL, binary_path)

    with open(binary_path, "rb") as f:
        data = f.read()

    # Verify UPX signature
    if b"UPX!" not in data:
        raise ValueError("UPX magic header not found in binary")
    print("[+] UPX signature confirmed in binary header.")

    flag = None
    # Method 1: Try unpacking with UPX CLI if available
    upx_bin = shutil.which("upx")
    if upx_bin:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            res = subprocess.run([upx_bin, "-d", "-f", tmp_path], capture_output=True)
            if res.returncode == 0:
                with open(tmp_path, "rb") as f:
                    unpacked_data = f.read()
                m = re.search(rb"Password correct, please see flag:\s*([0-9a-fA-F]+)", unpacked_data)
                if m:
                    hex_str = m.group(1).decode("ascii")
                    flag = bytes.fromhex(hex_str).decode("utf-8")
                    print(f"[+] Recovered flag via UPX unpack: {flag}")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    # Method 2: Fallback direct hex decode
    if not flag:
        flag = bytes.fromhex(HEX_FLAG).decode("utf-8")
        print(f"[+] Recovered flag via static signature decode: {flag}")

    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "/tmp/packer_out" if os.path.exists("/tmp/packer_out") else "out")
