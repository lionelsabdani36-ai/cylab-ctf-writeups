#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 256: bloat.py (picoCTF 2022)
Category: Reverse Engineering / Python AST Obfuscation & Stream XOR Deobfuscation
Difficulty: Medium | Points: 100
Author: LT 'syreal' Jones
Standard Reference: NIST SP 800-115 § 4.2 (Source Code Static Analysis & Obfuscation Deconstruction)
CWE: CWE-200 / CWE-798 (Hardcoded Password & Repeating XOR Key), CWE-327 (Broken Crypto Algorithm / Repeating-Key XOR)

Description:
Can you get the flag? Run this Python program:
https://challenge-files.cylabacademy.net/library/29555ba70e983dd8216407779bca6085b7eeab85c0c2a3a16d6b1c757a9eaa9c/bloat.flag.py
in the same directory as this encrypted flag:
https://challenge-files.cylabacademy.net/library/29555ba70e983dd8216407779bca6085b7eeab85c0c2a3a16d6b1c757a9eaa9c/flag.txt.enc

Vulnerability Analysis & Core Concept:
- String Literal Obfuscation via Character Array Indexing:
  The script defines an alphabet array containing printable ASCII characters:
    a = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "
  All sensitive strings (prompts, password check, and cryptographic keys) are constructed
  through array indexing:
  1. Password Verification (arg133):
     a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68] -> "happychance"
  2. XOR Keystream (arg111):
     a[81]+a[64]+a[79]+a[82]+a[66]+a[64]+a[75]+a[75]+a[72]+a[78]+a[77] -> "rapscallion"
- Reversible Repeating-Key XOR Encryption (CWE-327 / CWE-798):
  Function arg122 performs repeating-key XOR:
    C_i = P_i XOR K_(i mod len(K))
  Because XOR is its own inverse, and the secret key ("rapscallion") is embedded statically
  within the client-side code, the ciphertext can be decrypted deterministically without
  requiring interactive input or bypassing the password check dynamically.

Recovered Flag: academy{d30bfu5c4710n_f7w_d77083fe}
Verified: POST /api/submissions/ -> HTTP 201 Created (correct: true)
"""

import json
import os
import sys
import urllib.request

CHALLENGE_ID = 256
CHALLENGE_NAME = "bloat.py"
EXPECTED_FLAG = "academy{d30bfu5c4710n_f7w_d77083fe}"
URL_ENC = ("https://challenge-files.cylabacademy.net/library/"
           "29555ba70e983dd8216407779bca6085b7eeab85c0c2a3a16d6b1c757a9eaa9c/flag.txt.enc")

# Alphabet reconstructed from bloat.flag.py
ALPHABET = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "

# Statically resolved constants
PASSWORD = "".join(ALPHABET[i] for i in [71, 64, 79, 79, 88, 66, 71, 64, 77, 66, 68])
KEY = "".join(ALPHABET[i] for i in [81, 64, 79, 82, 66, 64, 75, 75, 72, 78, 77])

# Embedded 35-byte ciphertext from flag.txt.enc for 100% deterministic offline reproduction
EMBEDDED_ENC = bytes.fromhex(
    "13021117060c15170d5c5e1007054600555b5d5901311456072c07565b5c515c08171c"
)


def xor_decrypt(ciphertext: bytes, key: str) -> str:
    """Performs repeating-key XOR decryption matching arg122."""
    key_bytes = key.encode("utf-8")
    decrypted = [
        chr(b ^ key_bytes[i % len(key_bytes)])
        for i, b in enumerate(ciphertext)
    ]
    return "".join(decrypted)


def solve_offline() -> str:
    """Decodes flag using embedded ciphertext and statically derived key."""
    print(f"[*] Auditing Module {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print(f"[*] Stage 1: Deobfuscating Static Constants -> Password: '{PASSWORD}', Key: '{KEY}'")
    print(f"[*] Stage 2: Decrypting 35-byte embedded ciphertext stream...")
    flag = xor_decrypt(EMBEDDED_ENC, KEY)
    print(f"    [+] Decoded Stream: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


def solve(src: str | None = None) -> str:
    """Decodes flag from path, URL, or embedded bytes."""
    if src and os.path.isfile(src):
        with open(src, "rb") as f:
            data = f.read()
        return xor_decrypt(data, KEY)
    elif src and (src.startswith("http://") or src.startswith("https://")):
        req = urllib.request.Request(src, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = r.read()
        return xor_decrypt(data, KEY)
    else:
        # Try fetching from CDN if online, else fallback to embedded bytes
        try:
            req = urllib.request.Request(URL_ENC, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = r.read()
                return xor_decrypt(data, KEY)
        except Exception:
            return solve_offline()


def submit_to_cylab(token: str) -> bool:
    """Submits token to CyLab REST API verification gate."""
    sys.path.insert(0, "/tmp")
    try:
        import cylab_auth
        status, body = cylab_auth.req(
            "https://learn.cylabacademy.org/api/submissions/",
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        data = json.loads(body)
        return (status == 201 and data.get("correct") is True)
    except Exception as e:
        print(f"[-] Live submission check failed: {e}")
        return False


if __name__ == "__main__":
    s = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(s)
    print(f"[+] Output Flag: {flag}")
    assert flag == EXPECTED_FLAG
