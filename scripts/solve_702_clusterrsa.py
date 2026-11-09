#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: ClusterRSA (Challenge ID: 702)
Category: Cryptography / Multi-prime RSA & Clustered Modulus Factorization
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
NIST SP 800-56B Rev. 2 (Recommendation for Pair-Wise Key-Establishment Schemes Using Integer Factorization Cryptography),
RFC 8017 (PKCS #1 v2.2: RSA Cryptography Specifications - Multi-Prime RSA),
CWE-326 (Inadequate Encryption Strength), & CWE-310 (Cryptographic Issues).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - The challenge provides an artifact `message.txt` containing RSA parameters:
     n = 8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651 (333 bits)
     e = 65537
     ct = 6077311710730157058547975173005494694880887687368910290510611316416980539628903279743851720077932545
   - The user is asked to recover the plaintext flag from ciphertext `ct`.
2. Cryptographic Root Cause (CWE-326 / CWE-310):
   - Multi-Prime Decomposition & Insufficient Key Length: Rather than using two large balanced primes (e.g. 1024/2048 bits),
     the modulus n is composed of four distinct small primes (each ~83 bits).
   - Clustered Prime Factors: The four primes are tightly clustered near the fourth root of n (~9.6714e24):
     p1 = 9671406556917033397931773
     p2 = 9671406556917033398314601
     p3 = 9671406556917033398439721
     p4 = 9671406556917033398454847
   - Trivial Factorization: Because the primes are small and registered in public factorization databases (FactorDB),
     factoring n into p1 * p2 * p3 * p4 is instantaneous.
3. Cryptanalysis & Decryption Flow:
   - Step 1: Query FactorDB API or factorize n to extract primes [p1, p2, p3, p4].
   - Step 2: Compute Euler's totient function for multi-prime RSA: phi(n) = (p1 - 1) * (p2 - 1) * (p3 - 1) * (p4 - 1).
   - Step 3: Compute modular inverse private key d = pow(e, -1, phi(n)).
   - Step 4: Compute plaintext integer m = pow(ct, d, n).
   - Step 5: Convert m to ASCII bytes to extract the flag: `academy{mul71_rsa_411fc267}`.
"""

import os
import sys
import re
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 702
CHALLENGE_NAME = "ClusterRSA"
VERIFIED_FLAG = "academy{mul71_rsa_411fc267}"
COMMUNITY_FLAG = "CTF{mul71_rsa_411fc267}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# Default challenge parameters from message.txt
DEFAULT_N = 8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651
DEFAULT_E = 65537
DEFAULT_CT = 6077311710730157058547975173005494694880887687368910290510611316416980539628903279743851720077932545

# Factored 4 clustered prime factors
KNOWN_FACTORS = [
    9671406556917033397931773,
    9671406556917033398314601,
    9671406556917033398439721,
    9671406556917033398454847
]


def fetch_factors_from_factordb(n: int) -> list[int] | None:
    """Queries FactorDB REST API for prime decomposition."""
    url = f"http://factordb.com/api?query={n}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") in ("FF", "F"):
                factors = []
                for f, count in data.get("factors", []):
                    factors.extend([int(f)] * count)
                return factors
    except Exception:
        pass
    return None


def solve_multi_prime_rsa(n: int, e: int, ct: int, factors: list[int] | None = None) -> str:
    """Solves multi-prime RSA given modulus n, exponent e, ciphertext ct, and factors."""
    if not factors:
        factors = fetch_factors_from_factordb(n)
    if not factors and n == DEFAULT_N:
        factors = KNOWN_FACTORS

    if not factors:
        raise ValueError(f"Unable to factorize modulus n ({n})")

    prod_n = 1
    phi = 1
    for p in factors:
        prod_n *= p
        phi *= (p - 1)

    assert prod_n == n, f"Product of factors does not match n: {prod_n} != {n}"

    d = pow(e, -1, phi)
    m = pow(ct, d, n)
    flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
    flag = flag_bytes.decode("utf-8", errors="replace").strip()

    # Roundtrip verification: pow(m, e, n) == ct
    assert pow(m, e, n) == ct, "Roundtrip verification failed!"
    return flag


def solve(param_source=None) -> str:
    """Loads parameters from file, string, or defaults and returns decrypted flag."""
    n = DEFAULT_N
    e = DEFAULT_E
    ct = DEFAULT_CT

    if param_source and os.path.exists(param_source):
        with open(param_source, "r", encoding="utf-8") as f:
            content = f.read()
            m_n = re.search(r"n\s*=\s*(\d+)", content)
            m_e = re.search(r"e\s*=\s*(\d+)", content)
            m_ct = re.search(r"ct\s*=\s*(\d+)", content)
            if m_n:
                n = int(m_n.group(1))
            if m_e:
                e = int(m_e.group(1))
            if m_ct:
                ct = int(m_ct.group(1))

    return solve_multi_prime_rsa(n, e, ct)


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
    target_arg = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None
    flag = solve(target_arg)
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
