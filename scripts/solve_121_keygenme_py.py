#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 121: keygenme-py (picoCTF 2021)
Category: Reverse Engineering / Python AST Key Generation & Hash Inversion
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.3: Cryptographic & Binary Evaluation)
CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm / Hardcoded Dynamic Key Derivation)

Description:
A trial software written in Python checks license keys against a username.
By reverse-engineering the check_key function, the full license key (flag) is derived:
- Static prefix: academy{1n_7h3_kk3y_of_
- Dynamic section: 8 characters derived from sha256(b"MILLER") at offsets [4, 5, 3, 6, 2, 7, 1, 8]
- Static suffix: }

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import hashlib
import json
import os
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/2ae1afa675115ff8bf18b4d6edd0a7230c6231a75c3f5d33562372ee88be12cb/keygenme-trial.py"
EXPECTED_FLAG = "academy{1n_7h3_kk3y_of_9edf443b}"


def derive_flag(username: bytes = b"MILLER") -> str:
    """
    Reconstruct the full license key by reproducing check_key logic:
    static prefix + sha256(username)[indices] + static suffix
    """
    prefix = "academy{1n_7h3_kk3y_of_"
    suffix = "}"
    indices = [4, 5, 3, 6, 2, 7, 1, 8]

    h = hashlib.sha256(username).hexdigest()
    dynamic_part = "".join(h[i] for i in indices)
    return f"{prefix}{dynamic_part}{suffix}"


def main():
    print("[*] Reconstructing license key for keygenme-py...")
    flag = derive_flag(b"MILLER")
    print(f"[*] Generated Flag: {flag}")

    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] Key verification passed successfully!")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    main()
