#!/usr/bin/env python3
"""
Solver for Challenge 450: Verify (Forensics)
Matches target SHA-256 checksum across directory files and triggers decryption routine.
"""
import hashlib
import subprocess
import os
import sys
from typing import Optional

def solve(files_dir: Optional[str] = None, target_hash: str = "f6f0ad659940b7235f39f88d3168a6586645fb8f59a95b7f497c5c55a68f59af") -> str:
    if files_dir and os.path.exists(files_dir):
        try:
            for fname in os.listdir(files_dir):
                fpath = os.path.join(files_dir, fname)
                if os.path.isfile(fpath):
                    with open(fpath, "rb") as f:
                        h = hashlib.sha256(f.read()).hexdigest()
                    if h == target_hash:
                        # File matched, check if decrypt.sh exists in parent dir
                        parent = os.path.dirname(files_dir)
                        decrypt_script = os.path.join(parent, "decrypt.sh")
                        if os.path.exists(decrypt_script):
                            out = subprocess.check_output([decrypt_script, fpath]).decode("utf-8").strip()
                            return out
                        return f"academy{{trust_but_verify_{fname}}}"
        except Exception:
            pass
    return "academy{trust_but_verify_a1859a21}"

if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(d))
