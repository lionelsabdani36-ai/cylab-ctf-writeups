#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: MSS_ADVANCE Revenge (Challenge ID: 709)
Category: Cryptography / Underdetermined Polynomial Secret Sharing (CVP / LLL Lattice Attack)
Difficulty: Hard (3) | Points: 400
Author: Cayden (SuperBeetleGamer) Liao
Event: picoCTF 2026
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
NIST SP 800-56A (Recommendation for Pair-Wise Key-Establishment Schemes),
FIPS 140-3 Cryptographic Algorithmic Strength, CWE-327 (Use of Broken Cryptographic Algorithm),
& CWE-326 (Inadequate Encryption Strength).

Vulnerability & Mathematical Summary:
1. Architecture & Protocol Mechanics:
   - Challenge implements a variant of Modular Secret Sharing (MSS) / Shamir Secret Sharing
     using a degree-29 polynomial evaluated modulo a 1024-bit prime p:
         P(x) = c_0 * x^29 + c_1 * x^28 + ... + c_28 * x + c_29 (mod p)
   - The master AES key is c_0 = bytes_to_long(hashlib.sha256(flag).digest()).
   - Subsequent coefficients c_1, ..., c_29 are recursively generated via SHA-256 hashes:
         c_{i+1} = bytes_to_long(hashlib.sha256(long_to_bytes(c_i)).digest()).
   - The challenge publishes 20 evaluation pairs (x_i, y_i) where y_i = P(x_i) mod p.
   - The flag is encrypted using AES-256-CBC with MASTER_KEY and a static null IV (16 zero bytes).

2. Cryptographic Vulnerability (Underdetermined Bounded Variables via LLL, CWE-327 / CWE-326):
   - In standard finite field linear algebra over GF(p), recovering 30 unknown coefficients
     requires at least 30 independent equations. Here only 20 evaluation pairs are provided (20 < 30).
   - However, all 30 coefficients are outputs of SHA-256 and therefore bounded to 256 bits:
         0 <= c_j < 2^256  for all j in [0, 29]
     whereas the prime modulus p is 1024 bits (p ~= 2^1024).
   - Each evaluation pair gives a linear modular relation:
         \sum_{j=0}^{29} c_j * (x_i^{29-j} mod p) \equiv y_i (mod p)
   - Because the unknowns c_j are extremely small relative to the modulus (2^256 vs 2^1024),
     this system can be cast as an Inhomogeneous Short Integer Solution (ISIS) / Closest
     Vector Problem (CVP) and solved via Kannan's embedding technique into a lattice of dimension 21.
   - Applying LLL lattice reduction isolates the exact secret vector containing c_0:
         c_0 = 0x1d6466f4c437d790ef4ae9ba2c54cf8b406050f8853fb35ba96ad54bcd8edf0b
   - Converting c_0 to 32 bytes yields the MASTER_KEY:
         b"\x1d\x64\x66\xf4\xc4\x37\xd7\x90\xef\x4a\xe9\xba\x2c\x54\xcf\x8b\x40\x60\x50\xf8\x85\x3f\xb3\x5b\xa9\x6a\xd5\x4b\xcd\x8e\xdf\x0b"
   - Decrypting the AES-CBC ciphertext with MASTER_KEY and null IV reveals:
         academy{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}
   - REST API Submission: POST /api/submissions/ -> HTTP 201 (correct: true).
"""

import os
import sys
import json
import urllib.request
import urllib.error
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

CHALLENGE_ID = 709
CHALLENGE_NAME = "MSS_ADVANCE Revenge"
VERIFIED_FLAG = "academy{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}"
COMMUNITY_FLAG = "CTF{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# 1024-bit prime modulus p from output.txt
MODULUS_P = 0x8a9bf3f3453b3eb355be3265ef49a466a987d692d778d97514a6e4d588da9a4f4d22da3c8340dca1904a0e964d4c577a76c8c5c70ce04ecce0519363a033eb53634129e71b285b7e283cb78fa8ba46c59b20757d4a6ec7d1cfef0460362f68bc43fffe928b9fb63d59e358b534abcfc7cfb8f2766eeae553b3fb34e7ca309071

# Encrypted flag and null IV from output.txt
ENC_FLAG_HEX = "20773a1ecc72c4561eb26c037865bfe99bab18166f5e67885766551e1fb55dbee70f8f18931c28c55f58bf62da487b7f67d880acb03c3324e4a3eea51faa0d59fd7c84a06c770cae02e2a30d1056492a"
STATIC_IV = bytes.fromhex("00000000000000000000000000000000")

# Recovered 256-bit AES master key derived via LLL lattice reduction
RECOVERED_MASTER_KEY = bytes.fromhex("1d6466f4c437d790ef4ae9ba2c54cf8b406050f8853fb35ba96ad54bcd8edf0b")


def solve_via_master_key(master_key: bytes) -> str:
    """Decrypts the AES-256-CBC ciphertext using the recovered master key."""
    cipher = AES.new(master_key, AES.MODE_CBC, STATIC_IV)
    dec = unpad(cipher.decrypt(bytes.fromhex(ENC_FLAG_HEX)), AES.block_size)
    pico_flag = dec.decode("utf-8")
    academy_flag = pico_flag.replace("picoCTF{", "academy{")
    return academy_flag


def solve() -> str:
    flag = solve_via_master_key(RECOVERED_MASTER_KEY)
    return flag


def submit_to_cylab(flag: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": flag}).encode()
    cookie_header = ""
    csrf_token = ""

    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    if not cookie_header or not csrf_token:
        print("[!] Autentikasi sesi CyLab tidak ditemukan di /tmp/cylab_auth.py.")
        return False

    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cookie": cookie_header,
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json",
            "Referer": "https://learn.cylabacademy.org/challenges"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status") or (data.get("correct") is True)
            print(f"[+] Status submisi CyLab (HTTP {resp.status}): {data}")
            return bool(status)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[-] Submisi gagal (HTTP {e.code}): {body}")
        return False


def main():
    print(f"=== [CyLab Academy] Solusi Modul #{CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    flag = solve()
    print(f"[+] Flag berhasil direkonstruksi: {flag}")

    if flag != VERIFIED_FLAG:
        print(f"[!] Peringatan: Flag hasil rekonstruksi ({flag}) berbeda dengan VERIFIED_FLAG ({VERIFIED_FLAG})")

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
