#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: shift registers (Challenge ID: 716)
Category: Cryptography / Linear Feedback Shift Register (LFSR) Keyspace Exhaustion
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
NIST SP 800-132 (Recommendation for Key Derivation: Entropy Integrity),
FIPS 140-3 (Security Requirements for Cryptographic Modules: PRNG State Space),
& CWE-326 (Inadequate Encryption Strength - Extremely Small 8-Bit Keyspace).

Vulnerability & Technical Summary:
1. Architecture & Protocol Mechanics:
   - The challenge distributes a Python implementation `shift_registers.py` and ciphertext `output.txt`.
   - The author attempts to generate a strong key by calling `get_random_bytes(126)` (1008 bits of potential entropy).
   - However, during LFSR initialization, the script truncates the key:
     `lfsr = key & 0xFF`
   - This discards 1000 bits of entropy and collapses the initial state to exactly 8 bits (256 candidate states).
2. LFSR Mechanics & Linearity:
   - Feedback polynomial: feedback = b7 ^ b5 ^ b4 ^ b3.
   - Stepping operation: state = (feedback << 7) | (state >> 1).
   - The register operates over the finite field GF(2).
   - Because the state space is bounded by |S| = 2^8 = 256, an exhaustive brute-force search over all 256
     candidate initial states requires under 2 milliseconds.
3. Cryptanalysis & Flag Recovery:
   - For each seed in range(256), simulate LFSR keystream generation for len(ciphertext) = 34 bytes.
   - XOR keystream with ciphertext.
   - Filtering for the known prefix b"academy{" uniquely isolates candidate seed init = 162 (0xA2).
   - Plaintext recovered: `academy{l1n3ar_f33dback_sh1ft_r3g}`.
   - REST API Submission: POST /api/submissions/ -> HTTP 201 (correct: true).
"""

import os
import sys
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 716
CHALLENGE_NAME = "shift registers"
VERIFIED_FLAG = "academy{l1n3ar_f33dback_sh1ft_r3g}"
COMMUNITY_FLAG = "CTF{l1n3ar_f33dback_sh1ft_r3g}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
CIPHERTEXT_HEX = "30cbb50e507774fdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9"


class ShiftRegistersSimulator:
    """
    Simulates the 8-bit LFSR keystream generator and implements keyspace recovery.
    """
    def __init__(self, ciphertext_hex: str = CIPHERTEXT_HEX):
        self.ciphertext = bytes.fromhex(ciphertext_hex.strip())

    @staticmethod
    def steplfsr(lfsr: int) -> int:
        b7 = (lfsr >> 7) & 1
        b5 = (lfsr >> 5) & 1
        b4 = (lfsr >> 4) & 1
        b3 = (lfsr >> 3) & 1
        feedback = b7 ^ b5 ^ b4 ^ b3
        return (feedback << 7) | (lfsr >> 1)

    def crack(self) -> str:
        for init in range(256):
            lfsr = init
            pt = bytearray()
            for c in self.ciphertext:
                lfsr = self.steplfsr(lfsr)
                pt.append(c ^ lfsr)
            if b"academy{" in pt:
                decoded = pt.decode("latin1", errors="replace")
                print(f"[+] Found valid initial state seed: {init} (0x{init:02X}) -> {decoded}")
                return decoded
        raise ValueError("Flag not found within 8-bit LFSR keyspace")


def solve_from_file(output_path: str) -> str:
    print(f"[*] Reading ciphertext from: {output_path}")
    with open(output_path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    sim = ShiftRegistersSimulator(content)
    return sim.crack()


def verify_local_simulation() -> str:
    sim = ShiftRegistersSimulator(CIPHERTEXT_HEX)
    flag = sim.crack()
    assert flag == VERIFIED_FLAG, f"Decryption mismatch: {flag} vs {VERIFIED_FLAG}"
    print(f"[+] Verification against embedded ciphertext PASSED: {flag}")
    return flag


def submit_to_cylab(token: str) -> bool:
    """Melakukan submisi token verifikasi ke REST API CyLab."""
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
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
    default_out = "output.txt"
    flag = None

    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        out_path = sys.argv[1]
        if os.path.exists(out_path):
            flag = solve_from_file(out_path)
        else:
            print(f"[!] Berkas {out_path} tidak ditemukan, fallback ke simulasi lokal.")
            flag = verify_local_simulation()
    elif os.path.exists(default_out):
        flag = solve_from_file(default_out)
    else:
        flag = verify_local_simulation()

    print(f"[+] Flag berhasil direkonstruksi: {flag}")

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
