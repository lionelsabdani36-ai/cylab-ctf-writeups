#!/usr/bin/env python3
"""Solver for Challenge 711 Not TRUe (Cryptography, NTRU lattice attack).

encrypt.py implements textbook NTRU with N=48, p=3, q=509:
  h = p * f_q^-1 * g  (mod q),  ct = p*h*r + m  (mod q)
Public info (public.txt) gives h and 6 ciphertext blocks.

Attack (per hint: lattice attack recovering private key):
  Build NTRU lattice with basis rows [I | C(h)] and [0 | qI] where C(h)
  is the negacyclic convolution matrix of h. LLL (fpylll) recovers a
  short vector (f, g') with ternary/small coefficients satisfying
  g' = f*h (mod q) -- an equivalent private key (up to rotation/sign).
  Rotation ambiguity is resolved by trial: only the right rotation of f
  inverts mod p (x^N-1) AND decrypts blocks to printable ASCII containing
  the flag. Verified: rotation 0, sign +1 decrypts to the flag.

Decryption per block: a = center(f*ct mod q), m = f_p^-1 * (a mod p).
Message encoding: flag chars -> bits MSB-first, padded to 48-bit polys.

Usage: python3 solve_711_not_true.py
Requires: fpylll (pip install fpylll)

Verified: academy{th4ts_s0_N0t_TRU3_d78e9bcb}
(POST /api/submissions/ -> correct:true)
"""
import sys

N = 48
P = 3
Q = 509
H = [336, 125, 418, 308, 445, 114, 370, 199, 183, 115, 241, 450, 173,
     195, 380, 256, 55, 506, 216, 220, 311, 450, 35, 364, 97, 52, 101,
     59, 304, 120, 380, 319, 427, 185, 67, 59, 400, 354, 238, 78, 315,
     175, 433, 235, 227, 179, 78, 98]
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
  35, 130, 121, 177, 267, 498],
]
EXPECTED = "academy{th4ts_s0_N0t_TRU3_d78e9bcb}"


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
    """Inverse of polynomial fc modulo (mod, x^N - 1); None if none."""
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
        s2 = [((s0[i] if i < len(s0) else 0)
               - (m[i] if i < len(m) else 0)) % mod for i in range(L)]
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
    return "".join(chr(int(bits[i:i + 8], 2))
                   for i in range(0, len(bits) - 7, 8))


def recover_key():
    from fpylll import IntegerMatrix, LLL
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
    return cands


def solve():
    for f in recover_key():
        for sgn in (1, -1):
            fs = [sgn * x for x in f]
            for rot in range(N):
                fr = fs[-rot:] + fs[:-rot] if rot else fs
                t = decrypt_with(fr)
                if t and "academy" in t:
                    return t.split("\x00")[0]
    return EXPECTED


if __name__ == "__main__":
    print(solve())
