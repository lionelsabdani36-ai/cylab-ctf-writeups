#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: cryptomaze (Challenge ID: 703)
Category: Cryptography / LFSR Key Derivation & AES-128 ECB
Difficulty: Medium (2) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Security Testing and Analysis),
NIST SP 800-38A (Recommendation for Block Cipher Modes of Operation: Methods and Techniques),
FIPS 197 (Advanced Encryption Standard - AES), RFC 5652 (Cryptographic Message Syntax - PKCS#7),
CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), &
CWE-330 (Use of Insufficiently Random Values).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - The challenge provides an artifact `output.txt` containing the initial state and feedback taps
     of a 64-bit Linear Feedback Shift Register (LFSR) along with a 48-byte hexadecimal ciphertext.
   - Initial State: 64-element binary vector.
   - Feedback Taps: [63, 61, 60, 58].
   - Ciphertext: 48 bytes (3 AES blocks) encrypted under AES-ECB using a key derived from 128 clock
     cycles of the LFSR output bitstream.
2. Cryptographic Root Cause (CWE-327 / CWE-330):
   - Complete State & Parameter Exposure: PRNG security depends strictly on keeping seed/state private.
     Exposing the full register state and feedback polynomial eliminates all entropy.
   - Linear Predictability of LFSR: Linear Feedback Shift Registers are affine mappings over GF(2).
     Every generated bit is deterministic: feedback_t = state[63] ^ state[61] ^ state[60] ^ state[58].
   - Insecure Block Cipher Mode (ECB): Electronic Codebook mode processes blocks independently without IV
     or diffusion between blocks, vulnerable to pattern preservation.
3. Cryptanalysis & Recovery Flow:
   - Step 1: Simulate the 64-bit LFSR for 128 clock cycles to obtain the 128-bit keystream.
   - Step 2: Pack bits MSB-first into 16 bytes to reconstruct the 128-bit AES encryption key.
   - Step 3: Decrypt the 48-byte ciphertext using AES-128 in ECB mode.
   - Step 4: Remove PKCS#7 padding to reveal the flag: `academy{scr8mbledt_flvg_cc02eb30}`.
"""

import os
import sys
import re
import json
import urllib.request
import urllib.error
from Crypto.Cipher import AES

CHALLENGE_ID = 703
CHALLENGE_NAME = "cryptomaze"
VERIFIED_FLAG = "academy{scr8mbledt_flvg_cc02eb30}"
COMMUNITY_FLAG = "CTF{scr8mbledt_flvg_cc02eb30}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

STATE_INIT = [
    0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1,
    1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1
]
TAPS = [63, 61, 60, 58]
CIPHERTEXT_HEX = "5fdec2e502a7c8d5951f41da4b0e0057c0b35d156e1a3e569c6cbb212a5eb8e538338e7e04fbddef0c6260a4eb758417"


def derive_key(state_init=STATE_INIT, taps=TAPS, num_bits: int = 128) -> bytes:
    """Simulates LFSR clocking and derives AES key bytes."""
    state = list(state_init)
    bits = []
    for _ in range(num_bits):
        fb = 0
        for t in taps:
            fb ^= state[t]
        popped = state.pop(0)
        state.append(fb)
        bits.append(popped)

    key_bytes = bytearray()
    for i in range(0, num_bits, 8):
        chunk = bits[i:i + 8]
        val = 0
        for bit in chunk:
            val = (val << 1) | bit
        key_bytes.append(val)
    return bytes(key_bytes)


def solve(ct_hex: str = CIPHERTEXT_HEX) -> str:
    """Decrypts the ciphertext using the LFSR-derived AES-ECB key."""
    key = derive_key()
    ct = bytes.fromhex(ct_hex.strip())
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ct)

    pad_len = decrypted[-1]
    if 0 < pad_len <= 16 and decrypted[-pad_len:] == bytes([pad_len]) * pad_len:
        plaintext = decrypted[:-pad_len].decode("utf-8", errors="replace")
    else:
        plaintext = decrypted.decode("utf-8", errors="replace")
    return plaintext.strip()


def submit_to_cylab(flag: str) -> bool:
    """Submits verified flag to CyLab REST API."""
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
    target = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else CIPHERTEXT_HEX
    flag = solve(target)
    print(f"[+] Flag berhasil direkonstruksi: {flag}")

    assert flag == VERIFIED_FLAG, f"Flag mismatch: {flag} != {VERIFIED_FLAG}"
    print(f"[+] Integritas token terverifikasi 100%: {flag}")

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
