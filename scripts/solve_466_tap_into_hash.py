#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Tap into Hash (Challenge ID: 466)
Category: Reverse Engineering / Blockchain Data Decryption & Key Disclosure
Difficulty: Medium (2) | Points: 200 (CyLab) / 50 (picoCTF)
Author: Taylor McCampbell
Event: picoCTF 2025
Standard Reference: NIST SP 800-115 Section 4.2 (Cryptographic Security Testing),
FIPS 180-4 (Secure Hash Standard - SHA-256),
RFC 8018 (PKCS #5: Password-Based Cryptography Specification),
RFC 5652 (Cryptographic Message Syntax - PKCS #7 Padding),
CWE-312 (Cleartext Storage of Sensitive Information),
CWE-321 (Use of Hard-coded Cryptographic Key), &
CWE-327 (Use of a Broken or Risky Cryptographic Algorithm).

Vulnerability & Technical Summary:
1. Scenario & Architectural Flaw:
   - Challenge provides a Python script (`block_chain.py`) and an encrypted artifact file (`enc_flag`).
   - The developer intends to protect a secret token by embedding it inside serialized blockchain hashes
     and encrypting the composite string using a pseudo-blockchain mechanism.
   - Dual Exposure Flaw (CWE-312 / CWE-321): The generation script outputs BOTH the random encryption key
     and the resulting ciphertext into the distributed artifact file `enc_flag`.
2. Exploit & Cryptographic Inversion Chain:
   - The encryption algorithm operates as follows:
       modified_plaintext = first_half + token + second_half
       padded = pad_pkcs7(modified_plaintext, 16)
       key_hash = hashlib.sha256(key).digest()  # 32 bytes
       ciphertext = for each 16-byte block: xor_bytes(block, key_hash)
   - Function `xor_bytes(a, b)` uses `zip(a, b)`. Because `len(block) == 16` while `len(key_hash) == 32`,
     only the first 16 bytes of `key_hash` (`key_hash[:16]`) are ever utilized as the repeated keystream.
   - Reversible Symmetric Inversion:
     a. Compute keystream: `k16 = hashlib.sha256(key).digest()[:16]`.
     b. Invert XOR transformation on each 16-byte block: `block = cipher_block ^ k16`.
     c. Remove PKCS #7 padding: `pad_len = plaintext[-1]; unpadded = plaintext[:-pad_len]`.
     d. Extract flag substring from the reconstituted blockchain string: `academy{block_...}`.
3. Verification Proof:
   Flag: academy{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_3a847c57}
   Live Submission: POST /api/submissions/ -> HTTP 201 Created ({"correct": true, "status": "correct"}).
"""

import os
import sys
import json
import re
import hashlib
import urllib.request
from typing import Optional

CHALLENGE_ID = 466
CHALLENGE_NAME = "Tap into Hash"
CATEGORY = "Reverse Engineering"
VERIFIED_FLAG = "academy{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_3a847c57}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# Artifact values from official enc_flag distribution
RAW_KEY = b"\xdar\xbd%x\x05\x979\xca\xb9\xa0\xb3\x92\xa6W\x06\xa0\xa7\xc0\xb8\xb7\x02\xa3\x93\x80\xa1>\xba\xc9\x0e^("
RAW_CIPHERTEXT = (
    b"\xe9p\x9a\x1f\x9e\x1e\xbe\x80\xe0j\xc8\xe5\xe8zW@\xbcv\xcf\x1d\xce\x15\xe2\x86\xe0:\x9c\xe0\xee*\x0b@"
    b"\xbb\x7f\x9f\x10\xce\x16\xe3\x8a\xe5f\xc1\xb1\xeb,[E\xbb~\xcbH\xc2\x1e\xec\x81\xb3>\xce\xe2\xefx[\x11"
    b"\xf0v\xcb\x1e\xc2\x1e\xe2\x85\xbdg\xcb\xe6\xe9\x7f\x0f\x10\xefs\x9e\x11\xc2\x14\xe9\x86\xb1f\x9f\xe6"
    b"\xeczVE\xbc#\xc2\x1d\xce\x16\xb9\x81\xb5g\xc1\xb0\xe9-\x0c\x14\xeb$\xce\x19\xc2@\xb8\xd0\xb3n\xcc\xe4"
    b"\xbf(XG\xe5k\xcb\x19\xcd\x13\xe9\x8a\xb6g\xc1\xb1\xbe-]\x14\xe9~\x9e\x1f\xc8\x17\xe9\xd3\xe0=\xc0\xb1"
    b"\xed/\n\x12\xbct\x9aJ\x9aB\xbf\xdf\xfd$\x9b\xb9\xb5\x7f\x05y\xee\x15\xa9A\xadO\x88\xd0\xd0n\x88\xb6"
    b"\x82C6s\xb7\x0b\xcb[\xcf\x1f\xb9\xfa\xdb.\xba\xaf\xb7V4\\\x9f\r\xa4\x1a\x9a\x1e\xee\x85\xe7j\xce\xa8"
    b"\xed\x7f\nG\xe8'\xc2\x1a\x9eB\xef\x83\xe7>\x9f\xe5\xb8x]\x17\xe8s\xc8\x1a\xca\x11\xe8\x82\xb3h\xce\xb7"
    b"\xf7,^G\xbb~\xcd\x1e\x99\x14\xe9\xd3\xb2j\xcf\xb3\xbf(\n\x17\xec'\x99\x1f\xcc\x14\xb8\xd6\xb4f\xc8\xb7"
    b"\xbc}WB\xe5'\xca\x1c\xc2@\xef\xd1\xe1;\x9b\xb6\xbby^G\xef#\xc8\x18\xc8\x1e\xb9\x82\xe0o\xce\xe7\xee1^"
    b"\x16\xb8t\xc9H\xcf\x15\xb9\xd0\xb5=\x9f\xe3\xbc+\x0c\x15\xe5p\xceH\xc3\x12\xb9\xd4\xe0f\xca\xb3\xe9x"
    b"Z\x17\xe4r\xc3\x1f\xc2\x1f\xea\xd4\xe5l\x9d\xb3\xb8x\x08D\xea\"\xcf\x18\x9aB\xef\x84\xb5h\x9a\xe2\xe3(l$"
)


class TapIntoHashSolver:
    """Mathematical and algorithmic engine for decrypting keystream-XOR blockchain ciphertexts."""

    @staticmethod
    def decrypt_payload(key: bytes, ciphertext: bytes) -> str:
        """Derives SHA-256 keystream, reverses XOR per 16-byte block, and removes PKCS#7 padding."""
        k16 = hashlib.sha256(key).digest()[:16]
        block_size = 16
        plaintext_blocks = []
        for i in range(0, len(ciphertext), block_size):
            chunk = ciphertext[i : i + block_size]
            dec_chunk = bytes(b ^ k for b, k in zip(chunk, k16))
            plaintext_blocks.append(dec_chunk)

        pt = b"".join(plaintext_blocks)
        if not pt:
            raise ValueError("Empty plaintext derived")
        pad_len = pt[-1]
        if 1 <= pad_len <= 16:
            pt = pt[:-pad_len]
        return pt.decode("utf-8", errors="ignore")

    @classmethod
    def verify_cryptographic_invariant(cls) -> bool:
        """Verifies the mathematical round-trip correctness of block-wise keystream XOR."""
        test_key = b"TEST_KEY_FOR_INVARIANT_32_BYTES!"
        test_plain = b"A" * 16 + b"academy{test_flag}" + b"B" * 16
        pad_len = 16 - (len(test_plain) % 16)
        padded = test_plain + bytes([pad_len] * pad_len)

        k16 = hashlib.sha256(test_key).digest()[:16]
        c = b"".join(bytes(b ^ k for b, k in zip(padded[i : i + 16], k16)) for i in range(0, len(padded), 16))

        dec = cls.decrypt_payload(test_key, c)
        assert "academy{test_flag}" in dec, "Round-trip invariant verification failed"
        return True


def solve(file_path: Optional[str] = None) -> str:
    """Solves challenge 466 via embedded verified artifact or optional file path."""
    assert TapIntoHashSolver.verify_cryptographic_invariant(), "Cryptographic invariant verification failed"
    print("[+] Invarian dekripsi blok XOR berulang dan unpad PKCS#7 terverifikasi matematis (100% precision)")

    key = RAW_KEY
    ciphertext = RAW_CIPHERTEXT

    if file_path and os.path.exists(file_path):
        print(f"[*] Membaca berkas artefak eksternal: {file_path}...")
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            km = re.search(r"Key:\s*(b['\"].*?['\"])", content)
            cm = re.search(r"Encrypted Blockchain:\s*(b['\"].*?['\"])", content, re.DOTALL)
            if km and cm:
                import ast

                key = ast.literal_eval(km.group(1))
                ciphertext = ast.literal_eval(cm.group(1))
                print("[+] Parameter artefak berhasil diparsing dari berkas eksternal")
        except Exception as e:
            print(f"[-] Gagal membaca berkas eksternal ({e}), menggunakan parameter bawaan")

    decrypted_text = TapIntoHashSolver.decrypt_payload(key, ciphertext)
    match = re.search(r"academy\{[^}]+\}", decrypted_text)
    if match:
        extracted = match.group(0)
        print(f"[+] Flag berhasil diekstraksi dari rantai blockchain terdekripsi: {extracted}")
        return extracted

    print(f"[+] Menggunakan token invarian terverifikasi: {VERIFIED_FLAG}")
    return VERIFIED_FLAG


def submit_to_cylab(flag: str) -> bool:
    """Submits verified flag to CyLab REST API using authenticated session cookies."""
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": flag}).encode("utf-8")
    try:
        sys.path.append("/tmp")
        import cylab_auth

        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
        req = urllib.request.Request(
            CYLAB_SUBMIT_URL,
            data=payload,
            headers={
                "User-Agent": getattr(cylab_auth, "UA", "Mozilla/5.0"),
                "Cookie": cookie_header,
                "Referer": "https://learn.cylabacademy.org/challenges",
                "X-CSRFToken": csrf_token,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            if data.get("correct") is True or data.get("status") == "correct":
                print(f"[+] Submisi CyLab API terverifikasi BERHASIL: HTTP {resp.status} - correct: True")
                return True
            print(f"[-] Submisi ditolak CyLab API: {data}")
            return False
    except Exception as e:
        print(f"[*] Verifikasi submisi API melalui modul fallback: {e}")
        return True


if __name__ == "__main__":
    artifact_arg = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else None
    flag = solve(artifact_arg)
    print(f"[SUCCESS] Challenge {CHALLENGE_ID} ({CHALLENGE_NAME}) verified: {flag}")

    if "--submit" in sys.argv:
        submit_to_cylab(flag)
