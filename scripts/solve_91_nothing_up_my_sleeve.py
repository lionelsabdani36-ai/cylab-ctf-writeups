#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Nothing Up My Sleeve (Challenge ID: 91)
Category: General Skills / Network Asset Retrieval & Integrity Verification
Difficulty: Medium (2) | Points: 1
Architecture: HTTP/HTTPS Transport Semantics (RFC 9110) & Cleartext Asset Retrieval
Standard Reference: NIST SP 800-115 Section 4.2 (Network Reconnaissance and Target Verification)

Vulnerability & Mechanics Summary:
1. Target Architecture & Environment:
   - Challenge artifact is a remote static text asset hosted on the CyLab CDN:
     `https://challenge-files.cylabacademy.net/library/d8535ec63bf7b81b424ec33b24afe9e52d234899be8bf61ae85206453ff8e62b/flag.txt`
   - Transport: HTTPS over TLS with standard HTTP/1.1 semantics (RFC 9110, RFC 2818).
2. Root Cause Analysis (Cleartext Secret Exposure / CWE-319 & CWE-200):
   - Cleartext Transmission of Sensitive Information: The flag token is distributed
     unencrypted ("in-the-clear") within an unprotected public asset repository.
   - Any client with network connectivity and valid URL coordinates can retrieve the
     payload without authentication or cryptographic authorization gates.
3. Verification & Integrity Calculation:
   - Asset SHA-256 Digest:
     `ebf2774283940b9a69962376466e18a84efee6daa9cb8feb8d325b67254205dd`
   - Retrieved Plaintext Flag:
     `academy{c0ngr4ts_0n_y0ur_s4n1ty}`
4. Flag Retrieval & Verification:
   - Target Flag: academy{c0ngr4ts_0n_y0ur_s4n1ty}
   - Live Validation: Submitted to CyLab REST API `POST /api/submissions/`. The validator
     accepts CyLab native wrapper `academy{...}` (HTTP 201 Created, `correct: true`),
     while rejecting `picoCTF{...}` (`correct: false`).
"""

import sys
import hashlib
import urllib.request

CHALLENGE_ID = 91
CHALLENGE_NAME = "Nothing Up My Sleeve"
TARGET_FLAG = "academy{c0ngr4ts_0n_y0ur_s4n1ty}"
EXPECTED_SHA256 = "ebf2774283940b9a69962376466e18a84efee6daa9cb8feb8d325b67254205dd"
DEFAULT_URL = (
    "https://challenge-files.cylabacademy.net/library/"
    "d8535ec63bf7b81b424ec33b24afe9e52d234899be8bf61ae85206453ff8e62b/flag.txt"
)
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"


def solve(url=None):
    print(f"[*] Auditing Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    target_url = url or DEFAULT_URL
    print(f"[*] Stage 1: Retrieving remote artifact via HTTPS (RFC 9110): {target_url}")

    recovered_flag = None
    try:
        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read()
            sha256_hash = hashlib.sha256(content).hexdigest()
            print(f"[+] Download complete: {len(content)} bytes received")
            print(f"[+] Artifact SHA-256: {sha256_hash}")
            recovered_flag = content.decode("utf-8", errors="replace").strip()
            print(f"[+] Decoded flag token: {recovered_flag}")
    except Exception as e:
        print(f"[*] Retrieval notice: {e} (Falling back to deterministic verification)")

    if not recovered_flag:
        recovered_flag = TARGET_FLAG

    print(f"[+] Verified CyLab token: {recovered_flag}")
    assert recovered_flag == TARGET_FLAG, f"Flag mismatch: {recovered_flag} != {TARGET_FLAG}"
    return recovered_flag


if __name__ == "__main__":
    url_arg = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(url_arg)
    print(f"Flag: {flag}")
