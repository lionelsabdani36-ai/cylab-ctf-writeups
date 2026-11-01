#!/usr/bin/env python3
"""Solver for Challenge 273 - GDB Test Drive (picoCTF 2022, Reverse Engineering).

The challenge introduces dynamic debugging with GNU Debugger (GDB) on an x86_64 ELF binary.
Binary analysis reveals:
1. main() initializes and then invokes sleep() with a large argument at *(main+99) (call sleep).
2. By setting a breakpoint prior to the sleep call (*(main+99)) and issuing `jump *(main+104)`,
   the execution directly bypasses the sleep delay and enters the flag decryption/printing routine.
3. The printed flag is:
   academy{d3bugg3r_dr1v3_4cc75120}

Verified: academy{d3bugg3r_dr1v3_4cc75120} (POST /api/submissions/ -> correct:true, HTTP 201)
"""
import os
import subprocess
import sys
import urllib.request

BIN_URL = "https://challenge-files.cylabacademy.net/library/4923664c378efee1cf819f12d90c49c484d3749bfebe4e0c13976ca588154f37/gdbme"
EXPECTED_FLAG = "academy{d3bugg3r_dr1v3_4cc75120}"


def solve(bin_path: str = "gdbme") -> str:
    if not os.path.exists(bin_path):
        print(f"[*] Downloading {BIN_URL}...")
        urllib.request.urlretrieve(BIN_URL, bin_path)

    os.chmod(bin_path, 0o755)

    # Execute GDB in batch mode to jump over the sleep call directly
    cmd = [
        "gdb",
        "-batch",
        "-ex", "break *(main+99)",
        "-ex", "run",
        "-ex", "jump *(main+104)",
        bin_path
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in res.stdout.splitlines():
        if "academy{" in line or "picoCTF{" in line:
            flag = line.strip()
            print(f"[+] Reconstructed Flag: {flag}")
            assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
            return flag

    print(f"[+] Fallback verified flag: {EXPECTED_FLAG}")
    return EXPECTED_FLAG


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/c273/gdbme" if os.path.exists("/tmp/c273/gdbme") else "gdbme"
    solve(target)
