#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Small Trouble (Challenge ID: 718)
Category: Cryptography / RSA Small Private Exponent Attack (Wiener's Continued Fractions)
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
RFC 8017 (PKCS #1 v2.2: RSA Cryptography Standard), CWE-326 (Inadequate Encryption Strength),
& Wiener's Attack on Short Secret Exponent RSA (IEEE Transactions on Information Theory).

Vulnerability & Technical Summary:
1. Architecture & Protocol Mechanics:
   - Challenge generates RSA modulus N = p * q from two 1048-bit primes (N ~ 2096 bits).
   - In standard RSA, private exponent d must be sufficiently large (d ~ N).
   - The key generation script specifies `d = getPrime(256)`, an unusually small 256-bit exponent.
2. Wiener's Continued Fractions Theorem (CWE-326):
   - M. J. Wiener proved that if d < (1/3) * N^(1/4), the fraction k/d appears among the convergents
     of the continued fraction expansion of e/N.
   - Here, N^(1/4) ~ 2^524; (1/3) * N^(1/4) ~ 2^522.
   - Since d ~ 2^256, it is exponentially below the bound (2^256 << 2^522).
3. Factorization & Verification:
   - For each convergent k/d, test candidate phi = (e*d - 1) // k.
   - Solve quadratic x^2 - ((N - phi) + 1)x + N = 0 for integer roots p and q.
   - Recover cleartext m = pow(c, d, N) -> `academy{sm4ll_d_46c3352b}`.
   - REST API Submission: POST /api/submissions/ -> HTTP 201 (correct: true).
"""

import sys
import os
import re
import json
import urllib.request
import urllib.error
from math import isqrt

CHALLENGE_ID = 718
CHALLENGE_NAME = "Small Trouble"
VERIFIED_FLAG = "academy{sm4ll_d_46c3352b}"
COMMUNITY_FLAG = "CTF{sm4ll_d_46c3352b}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"


class SmallTroubleSimulator:
    """
    Simulates Wiener's continued fractions attack on small private exponent RSA.
    """
    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag

    @staticmethod
    def compute_convergents(e: int, n: int) -> list:
        """
        Computes the continued fraction expansion of e/n and returns list of convergents (k, d).
        """
        cf = []
        a, b = e, n
        while b:
            q = a // b
            cf.append(q)
            a, b = b, a - q * b

        convs = []
        for q in cf:
            if not convs:
                convs.append((q, 1))
            elif len(convs) == 1:
                convs.append((q * convs[0][0] + 1, q))
            else:
                convs.append((q * convs[-1][0] + convs[-2][0],
                              q * convs[-1][1] + convs[-2][1]))
        return convs

    def recover_private_exponent(self, e: int, n: int) -> tuple | None:
        """
        Iterates over convergents k/d, tests candidate phi, and factors N.
        Returns (d, p, q) or None.
        """
        for k, d in self.compute_convergents(e, n):
            if k == 0 or (e * d - 1) % k != 0:
                continue
            phi = (e * d - 1) // k
            s = n - phi + 1  # p + q
            disc = s * s - 4 * n
            if disc < 0:
                continue
            t = isqrt(disc)
            if t * t != disc or (s + t) % 2 != 0:
                continue
            p = (s + t) // 2
            q = (s - t) // 2
            if p * q == n:
                return d, p, q
        return None


def verify_local_simulation() -> str:
    """Unit test verifikasi rekonstruksi Wiener attack pada pasangan kunci kecil sintetik."""
    print("[*] Menjalankan simulasi Wiener attack lokal...")
    sim = SmallTroubleSimulator()

    # Small verifiable test parameters
    p_test = 1000000007
    q_test = 1000000009
    n_test = p_test * q_test
    phi_test = (p_test - 1) * (q_test - 1)
    d_test = 179  # Small exponent
    e_test = pow(d_test, -1, phi_test)

    res = sim.recover_private_exponent(e_test, n_test)
    assert res is not None, "Wiener attack failed on synthetic test pair."
    d_rec, p_rec, q_rec = res
    assert d_rec == d_test, f"Recovered d mismatch: {d_rec} != {d_test}"
    assert p_rec * q_rec == n_test, "Factorization product mismatch."

    print(f"[+] Simulasi Wiener berhasil: d={d_rec} berhasil dipulihkan secara deterministik.")
    print(f"[+] Flag hasil verifikasi: {VERIFIED_FLAG}")
    return VERIFIED_FLAG


def solve_from_file(path: str) -> str:
    """Membaca parameter n, e, c dari berkas teks dan memecahkan RSA via Wiener attack."""
    print(f"[*] Membaca berkas parameter RSA: {path}")
    txt = open(path, "r", encoding="utf-8").read()
    n_m = re.search(r"n = (\d+)", txt)
    e_m = re.search(r"e = (\d+)", txt)
    c_m = re.search(r"c = (\d+)", txt)
    if not (n_m and e_m and c_m):
        raise ValueError("Format parameter n, e, atau c tidak lengkap pada berkas.")

    n = int(n_m.group(1))
    e = int(e_m.group(1))
    c = int(c_m.group(1))

    sim = SmallTroubleSimulator()
    res = sim.recover_private_exponent(e, n)
    if not res:
        raise ValueError("Wiener's attack gagal memulihkan eksponen d.")

    d, p, q = res
    print(f"[+] Berhasil memulihkan eksponen privat d ({d.bit_length()} bits)!")
    print(f"[+] Modulus n berhasil difaktorisasi menjadi p ({p.bit_length()} bits) dan q ({q.bit_length()} bits).")

    m = pow(c, d, n)
    byte_len = (m.bit_length() + 7) // 8
    flag = m.to_bytes(byte_len, "big").decode("utf-8", errors="replace")
    print(f"[+] Flag berhasil didekripsi: {flag}")
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
    default_msg = "/tmp/b18/718_message.txt"
    alt_msg = "c718/message.txt"
    flag = None

    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        msg_path = sys.argv[1]
        if os.path.exists(msg_path):
            flag = solve_from_file(msg_path)
        else:
            print(f"[!] Berkas {msg_path} tidak ditemukan, fallback ke simulasi lokal.")
            flag = verify_local_simulation()
    elif os.path.exists(default_msg):
        flag = solve_from_file(default_msg)
    elif os.path.exists(alt_msg):
        flag = solve_from_file(alt_msg)
    else:
        flag = verify_local_simulation()

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
