#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Black Cobra Pepper (Challenge ID: 701)
Category: Cryptography / Linear Affine Cryptanalysis over GF(2) (AES without S-Box)
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
FIPS 197 (Advanced Encryption Standard - AES), ISO/IEC 18033-3 (Block Ciphers),
CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), &
CWE-310 (Cryptographic Issues).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge provides an AES-like cipher script `chall.py` and output file `output.txt`.
   - In `chall.py`, the core non-linear substitution components are replaced with identity functions:
     `sub_bytes()` and `sub_word()` return input unchanged, and round constants `rcon()` are identity/omitted.
   - `output.txt` provides:
     - ct1: Ciphertext corresponding to known plaintext pt1 = "randomdata111111" (hex: 72616e646f6d64617461313131313131)
     - ct2: Ciphertext of the unknown flag.
2. Cryptographic Root Cause (CWE-327 / CWE-310):
   - Total Loss of Non-Linear Confusion: AES relies on the non-linear S-Box (multiplicative inversion in GF(2^8)
     followed by affine mapping) to defeat linear cryptanalysis.
   - Reduction to Affine Transformation over GF(2): Without S-boxes, all operations (AddRoundKey, ShiftRows,
     MixColumns, and linear key scheduling) are strictly affine transformations over GF(2)^128:
         E_k(p) = L(p) XOR F(k)
     where L is a key-independent linear transformation, and F(k) is a key-dependent offset.
   - Zero-Key Fixed Point: When k = 0, all round keys rk_i = 0, so F(0) = 0.
     Thus, L(p) = E_0(p) is directly computable by running the cipher with a zero key.
3. Cryptanalysis & Recovery Flow:
   - Step 1: Compute key offset F(k) = ct1 XOR E_0(pt1) using the known plaintext-ciphertext pair.
   - Step 2: Unmask the flag's linear component: L(flag) = ct2 XOR F(k).
   - Step 3: Invert L using the zero-key decryption routine: flag = D_0(L(flag)).
   - Step 4: Convert flag bytes to ASCII: `academy{spi1cy!}`.
"""

import os
import sys
import re
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 701
CHALLENGE_NAME = "Black Cobra Pepper"
VERIFIED_FLAG = "academy{spi1cy!}"
COMMUNITY_FLAG = "CTF{spi1cy!}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# Default parameters from challenge output.txt
DEFAULT_PT1 = "72616e646f6d64617461313131313131"  # "randomdata111111"
DEFAULT_CT1 = "d7481d89f1aaf5a857f56edd2ae8994c"
DEFAULT_CT2 = "e5506260c6369f5d948419c2955fa236"


def bxor(a: bytes, b: bytes) -> bytes:
    """Byte-wise XOR."""
    return bytes(x ^ y for x, y in zip(a, b))


def split(k: str) -> list[str]:
    """Splits key hex into 4 sub-blocks."""
    subs = ["", "", "", ""]
    for i in range(len(k)):
        subs[i % 4] += k[0]
        k = k[1:]
    return subs


def glue(parts: list) -> str:
    """Reassembles 4 sub-blocks into hex string."""
    parts = [list(p) for p in parts]
    return "".join(parts[i % 4].pop(0) for i in range(32))


def gen_keys(mk: str) -> list[str]:
    """Generates round keys without S-box substitution."""
    keys, k = [], mk
    for _ in range(11):
        keys.append(k)
        s = split(k)
        s[-1] = s[-1][2:] + s[-1][:2]  # rot_word
        s[0] = bxor(bytes.fromhex(s[0]), bytes.fromhex(s[-1])).hex()
        s[1] = bxor(bytes.fromhex(s[1]), bytes.fromhex(s[0])).hex()
        s[2] = bxor(bytes.fromhex(s[2]), bytes.fromhex(s[1])).hex()
        s[3] = bxor(bytes.fromhex(s[3]), bytes.fromhex(s[2])).hex()
        k = glue(s)
    return keys


def to_mat(h: str) -> list[list[int]]:
    """Converts 32 hex chars to 4x4 byte matrix."""
    bl = [int(h[i:i + 2], 16) for i in range(0, 32, 2)]
    return [[bl[r + 4 * c] for c in range(4)] for r in range(4)]


def from_mat(m: list[list[int]]) -> str:
    """Converts 4x4 matrix back to 32 hex chars."""
    return "".join("%02x" % m[r][c] for c in range(4) for r in range(4))


def shift(s: list[list[int]], inv: bool = False) -> list[list[int]]:
    """Performs AES ShiftRows or InvShiftRows."""
    r = [row[:] for row in s]
    r[1] = (r[1][3:] + r[1][:3]) if inv else (r[1][1:] + r[1][:1])
    r[2] = r[2][2:] + r[2][:2]
    r[3] = (r[3][1:] + r[3][:1]) if inv else (r[3][3:] + r[3][:3])
    return r


def gmul(a: int, b: int) -> int:
    """Galois field GF(2^8) multiplication modulo irreducible polynomial 0x11b."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b >>= 1
    return p


def mix(s: list[list[int]], inv: bool = False) -> list[list[int]]:
    """Performs AES MixColumns or InvMixColumns."""
    C = (0x0e, 0x0b, 0x0d, 0x09) if inv else (0x02, 0x03, 0x01, 0x01)
    o = [[0] * 4 for _ in range(4)]
    for c in range(4):
        o[0][c] = gmul(C[0], s[0][c]) ^ gmul(C[1], s[1][c]) ^ gmul(C[2], s[2][c]) ^ gmul(C[3], s[3][c])
        o[1][c] = gmul(C[3], s[0][c]) ^ gmul(C[0], s[1][c]) ^ gmul(C[1], s[2][c]) ^ gmul(C[2], s[3][c])
        o[2][c] = gmul(C[2], s[0][c]) ^ gmul(C[3], s[1][c]) ^ gmul(C[0], s[2][c]) ^ gmul(C[1], s[3][c])
        o[3][c] = gmul(C[1], s[0][c]) ^ gmul(C[2], s[1][c]) ^ gmul(C[3], s[2][c]) ^ gmul(C[0], s[3][c])
    return o


def enc(pt_hex: str, key_hex: str) -> str:
    """Encrypts one block under S-Box-less AES."""
    rk = gen_keys(key_hex)
    st = bxor(bytes.fromhex(pt_hex), bytes.fromhex(rk[0])).hex()
    for i in range(1, 10):
        st = from_mat(mix(shift(to_mat(st))))
        st = bxor(bytes.fromhex(st), bytes.fromhex(rk[i])).hex()
    st = from_mat(shift(to_mat(st)))
    return bxor(bytes.fromhex(st), bytes.fromhex(rk[10])).hex()


def dec(ct_hex: str, key_hex: str) -> str:
    """Decrypts one block under S-Box-less AES."""
    rk = gen_keys(key_hex)
    st = to_mat(bxor(bytes.fromhex(ct_hex), bytes.fromhex(rk[10])).hex())
    st = shift(st, True)
    for i in range(9, 0, -1):
        st = to_mat(bxor(bytes.fromhex(from_mat(st)), bytes.fromhex(rk[i])).hex())
        st = shift(mix(st, True), True)
    return bxor(bytes.fromhex(from_mat(st)), bytes.fromhex(rk[0])).hex()


def solve(pt1: str = DEFAULT_PT1, ct1: str = DEFAULT_CT1, ct2: str = DEFAULT_CT2) -> str:
    """Executes affine cryptanalysis on S-Box-less AES."""
    zero = "00" * 32
    fk = bxor(bytes.fromhex(ct1), bytes.fromhex(enc(pt1, zero))).hex()
    flag_hex = dec(bxor(bytes.fromhex(ct2), bytes.fromhex(fk)).hex(), zero)
    return bytes.fromhex(flag_hex).decode("utf-8", errors="replace").strip()


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
    pt1, ct1, ct2 = DEFAULT_PT1, DEFAULT_CT1, DEFAULT_CT2

    # Check for CLI arguments or local file
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if len(args) == 3:
        pt1, ct1, ct2 = args[0], args[1], args[2]
    elif len(args) == 1 and os.path.exists(args[0]):
        with open(args[0], "r") as f:
            lines = [l.strip() for l in f if l.strip()]
            if len(lines) >= 2:
                ct1, ct2 = lines[0], lines[1]

    flag = solve(pt1, ct1, ct2)
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
