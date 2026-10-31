#!/usr/bin/env python3
"""Solver for Challenge 375 - Safe Opener 2 (picoCTF 2023, Reverse Engineering).

The challenge provides a compiled Java class file (SafeOpener.class).
Static analysis of the Java bytecode reveals:
1. The Java class file follows the standard JVM class file format (magic: 0xCAFEBABE).
2. The constant pool table (cp_info) contains CONSTANT_Utf8 (tag 1) structures.
3. The password string used to unlock the safe is embedded directly as a plaintext
   string literal in the constant pool:
   academy{SAf3_0p3n3rr_y0u_solv3d_it_7f70e636}

Verified: academy{SAf3_0p3n3rr_y0u_solv3d_it_7f70e636} (POST /api/submissions/ -> correct:true)
"""
import os
import re
import sys
import urllib.request

CLASS_URL = "https://challenge-files.cylabacademy.net/library/5c5f8143dd09275a5ecdd390027ea5488159881d757099706515c4cbf15992f1/SafeOpener.class"
EXPECTED_FLAG = "academy{SAf3_0p3n3rr_y0u_solv3d_it_7f70e636}"


def solve(class_path: str = "SafeOpener.class") -> str:
    if not os.path.exists(class_path):
        print(f"[*] Downloading {CLASS_URL}...")
        urllib.request.urlretrieve(CLASS_URL, class_path)

    with open(class_path, "rb") as f:
        data = f.read()

    # Validate Java class magic header 0xCAFEBABE
    if len(data) < 4 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("Invalid Java class file header (expected 0xCAFEBABE)")

    match = re.search(rb"(?:academy|picoCTF|CTF)\{[^}]+\}", data)
    if not match:
        raise ValueError("Flag not found in Java class file constant pool")

    flag = match.group(0).decode("utf-8", errors="replace")
    print(f"[+] Recovered flag from Java constant pool: {flag}")
    assert flag == EXPECTED_FLAG
    return flag


if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "/tmp/SafeOpener.class" if os.path.exists("/tmp/SafeOpener.class") else "SafeOpener.class")
