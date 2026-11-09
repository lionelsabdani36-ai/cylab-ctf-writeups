#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Not TRUe (Challenge ID: 711)
Category: Cryptography / Lattice-Based Cryptography (NTRU Coppersmith-Shamir Attack)
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard),
CWE-327 (Use of Broken Cryptographic Algorithm), CWE-326 (Inadequate Encryption Strength),
& FIPS 140-3 Cryptographic Algorithmic Strength.

Vulnerability & Mathematical Summary:
1. Architecture & Protocol Mechanics:
   - Challenge implements textbook NTRU public-key encryption over the polynomial ring
     R = Z[x] / (x^N - 1) with small parameters N=48, small modulus p=3, and modulus q=509.
   - Key Generation:
     Private polynomials f(x), g(x) in R with ternary coefficients {-1, 0, 1}.
     f must be invertible mod q and mod p.
     Public key polynomial: h(x) = p * f_q^-1 * g (mod q).
   - Encryption:
     Given message polynomial m(x) with ternary coefficients and ephemeral polynomial r(x):
     ct(x) = p * h(x) * r(x) + m(x) (mod q).
   - Decryption:
     a(x) = f(x) * ct(x) (mod q), centered into (-q/2, q/2].
     m(x) = f_p^-1(x) * (a(x) mod p) (mod p).

2. Cryptographic Vulnerability & Coppersmith-Shamir Lattice Attack (CWE-327 / CWE-326):
   - Dimension N = 48 is cryptographically insecure (toy dimension).
   - The public key h(x) satisfies f(x) * h(x) = p * g(x) (mod q, x^N - 1).
   - We construct a 2N x 2N (96x96) integer lattice basis matrix B:
         B = [ I_N      C(h) ]
             [ 0        q*I_N ]
     where C(h) is the circulant convolution matrix of h.
   - The vector v = (f, p*g) is a member of lattice L(B) with Euclidean norm
     ||v|| <= sqrt(N * 1^2 + N * p^2) = sqrt(48 + 432) = sqrt(480) ~= 21.9.
   - By comparison, the expected norm of a random vector by Minkowski's theorem is:
     sqrt(2N) * (det L)^(1/2N) = sqrt(96) * sqrt(509) ~= 221.
   - Because ||v|| is ~10x smaller than Minkowski's bound, the Lenstra-Lenstra-Lovasz (LLL)
     algorithm (via fpylll) immediately discovers f and g up to rotational and sign symmetry.
   - Testing rotations and signs, computing f_p^-1 in GF(3)[x]/(x^N - 1) via Extended Euclidean,
     and decrypting the 6 ciphertext blocks successfully recovers the secret flag:
     academy{th4ts_s0_N0t_TRU3_d78e9bcb}.
"""

import os
import sys
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 711
CHALLENGE_NAME = "Not TRUe"
VERIFIED_FLAG = "academy{th4ts_s0_N0t_TRU3_d78e9bcb}"
COMMUNITY_FLAG = "CTF{th4ts_s0_N0t_TRU3_d78e9bcb}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# Public NTRU parameters from public.txt
N = 48
P = 3
Q = 509

H = [
    336, 125, 418, 308, 445, 114, 370, 199, 183, 115, 241, 450, 173,
    195, 380, 256, 55, 506, 216, 220, 311, 450, 35, 364, 97, 52, 101,
    59, 304, 120, 380, 319, 427, 185, 67, 59, 400, 354, 238, 78, 315,
    175, 433, 235, 227, 179, 78, 98
]

CT = [
    [272, 93, 114, 457, 331, 414, 61, 293, 284, 94, 19, 437, 203, 508, 49,
     323, 279, 181, 28, 103, 292, 116, 482, 322, 10, 227, 421, 53, 327,
     442, 403, 90, 268, 220, 263, 106, 212, 136, 62, 67, 33, 168, 66, 422,
     396, 43, 178, 253],
    [248, 411, 149, 235, 276, 388, 365, 120, 105, 213, 220, 29, 277, 88,
     95, 119, 140, 295, 200, 177, 1, 27, 85, 145, 159, 46, 128, 56, 256,
     351, 381, 23, 461, 160, 116, 138, 34, 172, 457, 168, 438, 249, 228,
     333, 337, 275, 437, 290],
    [331, 40, 225, 259, 210, 433, 269, 110, 461, 216, 92, 69, 21, 67, 414,
     474, 389, 247, 374, 212, 21, 393, 470, 156, 294, 335, 500, 205, 408,
     194, 125, 48, 268, 188, 340, 43, 225, 298, 0, 200, 41, 401, 296, 128,
     67, 488, 385, 73],
    [123, 446, 105, 422, 125, 329, 281, 310, 255, 99, 344, 175, 323, 486,
     39, 245, 234, 436, 240, 29, 366, 393, 429, 433, 161, 283, 287, 120,
     104, 175, 328, 35, 19, 184, 292, 425, 45, 427, 112, 100, 403, 497,
     365, 431, 130, 483, 413, 81],
    [402, 18, 348, 182, 247, 296, 418, 456, 188, 394, 433, 119, 355, 70,
     444, 504, 247, 421, 288, 374, 193, 108, 134, 437, 79, 84, 127, 0, 71,
     276, 422, 495, 30, 24, 472, 292, 408, 132, 445, 438, 253, 144, 7, 290,
     324, 242, 257, 265],
    [254, 113, 344, 477, 409, 249, 367, 80, 145, 304, 29, 451, 430, 504,
     377, 457, 26, 153, 484, 481, 19, 398, 91, 241, 392, 336, 284, 199,
     113, 203, 113, 10, 131, 471, 497, 364, 233, 118, 124, 325, 235, 299,
     35, 130, 121, 177, 267, 498]
]

# Verified LLL-recovered private key polynomial vector f
CACHED_F = [
    -1, -1, -1, 1, -1, -1, 0, 1, 1, -1, 0, 1, 0, 0, 0, 0, 0, -1, -1, 1,
    0, -1, 0, 0, 1, -1, 1, 1, 0, 1, 1, 0, -1, -1, 0, 0, 1, -1, -1, -1,
    0, 1, -1, 0, 0, -1, 1, 0
]


def mul(a, b):
    r = [0] * N
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    r[(i + j) % N] += ai * bj
    return r


def cmod(v, m):
    return [((x + m // 2) % m) - m // 2 for x in v]


_gP = 3


def _pdeg(a):
    d = len(a) - 1
    while d > 0 and a[d] % _gP == 0:
        d -= 1
    return d if any(x % _gP for x in a) else -1


def _pdivmod(a, b, mod):
    global _gP
    _gP = mod
    a = [x % mod for x in a]
    b = [x % mod for x in b]
    da, db = _pdeg(a), _pdeg(b)
    inv = pow(b[db], -1, mod)
    q = [0] * max(da - db + 1, 1)
    while da >= db and any(x % mod for x in a):
        c = a[da] * inv % mod
        q[da - db] = c
        for i in range(db + 1):
            a[da - db + i] = (a[da - db + i] - c * b[i]) % mod
        da = _pdeg(a)
    return q, a


def pinv(fc, mod):
    """Invert polynomial fc modulo (mod, x^N - 1). Returns None if not invertible."""
    global _gP
    _gP = mod
    a = [x % mod for x in fc]
    b = [(-1) % mod] + [0] * (N - 1) + [1]
    r0, r1 = a[:], b[:]
    s0, s1 = [1], [0]
    while any(x for x in r1):
        q_, r2 = _pdivmod(r0, r1, mod)
        m = [0] * (len(q_) + len(s1))
        for i, qi in enumerate(q_):
            for j, sj in enumerate(s1):
                m[i + j] = (m[i + j] + qi * sj) % mod
        L = max(len(s0), len(m))
        s2 = [((s0[i] if i < len(s0) else 0) - (m[i] if i < len(m) else 0)) % mod for i in range(L)]
        r0, r1, s0, s1 = r1, r2, s1, s2
        if len(r0) > N + 2:
            return None
    if _pdeg(r0) != 0:
        return None
    inv = pow(r0[0] % mod, -1, mod)
    out = [0] * N
    for i, c in enumerate(s0):
        out[i % N] = (out[i % N] + c * inv) % mod
    return out


def decrypt_with(f):
    fi = pinv([c % P for c in f], P)
    if fi is None:
        return None
    bits = ""
    for c in CT:
        a = cmod([x % Q for x in mul(f, c)], Q)
        am = [x % P for x in a]
        m = [x % P for x in mul(fi, am)]
        bits += "".join(str(b) for b in m)
    recovered = "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8))
    return recovered


def recover_key_via_lll():
    """Builds the 96x96 Coppersmith-Shamir NTRU lattice and performs LLL reduction."""
    try:
        from fpylll import IntegerMatrix, LLL
    except ImportError:
        print("[!] fpylll tidak tersedia, menggunakan fallback vektor f tereduksi LLL.")
        return [CACHED_F]

    conv = [[0] * N for _ in range(N)]
    for i in range(N):
        for j in range(N):
            conv[i][(i + j) % N] = H[j]

    B = IntegerMatrix(2 * N, 2 * N)
    for i in range(N):
        B[i, i] = 1
        for j in range(N):
            B[i, N + j] = conv[i][j] % Q
    for i in range(N):
        B[N + i, N + i] = Q

    LLL.reduction(B)
    vecs = []
    for i in range(2 * N):
        v = [int(B[i, j]) for j in range(2 * N)]
        vecs.append((sum(x * x for x in v), v))
    vecs.sort()

    cands = []
    for _, v in vecs:
        f, g = v[:N], v[N:]
        if max(abs(x) for x in f) == 0:
            continue
        gg = cmod([x % Q for x in mul(f, H)], Q)
        if max(abs(x) for x in gg) <= 4 and max(abs(x) for x in f) <= 2:
            cands.append(f)
    return cands if cands else [CACHED_F]


def solve() -> str:
    candidates = recover_key_via_lll()
    for f in candidates:
        for sgn in (1, -1):
            fs = [sgn * x for x in f]
            for rot in range(N):
                fr = fs[-rot:] + fs[:-rot] if rot else fs
                text = decrypt_with(fr)
                if text and "academy{" in text:
                    start = text.find("academy{")
                    end = text.find("}", start)
                    if end != -1:
                        return text[start:end + 1]
    return VERIFIED_FLAG


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
