#!/usr/bin/env python3
"""Solver for Challenge 701 Black Cobra Pepper (picoCTF 2026, Cryptography).

chall.py implements AES-128 EXCEPT sub_bytes()/sub_word() are the identity
and rcon() is identity — the S-box is gone. Every remaining operation
(AddRoundKey, ShiftRows, MixColumns, key schedule) is GF(2)-linear, so the
whole cipher is an AFFINE map:

    E_k(pt) = L(pt) XOR F(k)

with key-independent linear part L and key-dependent offset F. The zero key
is a fixed point of the key schedule (split/rot/xor/glue of zeros = zeros),
so all 11 round keys are 0 and L(pt) = E_0(pt) is directly computable.
Hence F(k) = ct1 XOR E_0(pt1) from the known pair, and

    flag = D_0(ct2 XOR ct1 XOR E_0(pt1))     (D_0 = decrypt with key 0)

Recovered: academy{spi1cy!} (verified POST /api/submissions/ -> correct:true)

Usage: solve_701_black_cobra_pepper.py  (reads c701/output.txt or args)
       solve_701_black_cobra_pepper.py <pt1hex> <ct1hex> <ct2hex>
"""
import sys

EXPECTED = "academy{spi1cy!}"


def bxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def split(k):
    subs = ["", "", "", ""]
    for i in range(len(k)):
        subs[i % 4] += k[0]
        k = k[1:]
    return subs


def glue(parts):
    parts = [list(p) for p in parts]
    return "".join(parts[i % 4].pop(0) for i in range(32))


def gen_keys(mk):
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


def to_mat(h):
    bl = [int(h[i:i + 2], 16) for i in range(0, 32, 2)]
    return [[bl[r + 4 * c] for c in range(4)] for r in range(4)]


def from_mat(m):
    return "".join("%02x" % m[r][c] for c in range(4) for r in range(4))


def shift(s, inv=False):
    r = [row[:] for row in s]
    r[1] = (r[1][3:] + r[1][:3]) if inv else (r[1][1:] + r[1][:1])
    r[2] = r[2][2:] + r[2][:2]
    r[3] = (r[3][1:] + r[3][:1]) if inv else (r[3][3:] + r[3][:3])
    return r


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b >>= 1
    return p


def mix(s, inv=False):
    C = (0x0e, 0x0b, 0x0d, 0x09) if inv else (0x02, 0x03, 0x01, 0x01)
    o = [[0] * 4 for _ in range(4)]
    for c in range(4):
        o[0][c] = gmul(C[0], s[0][c]) ^ gmul(C[1], s[1][c]) ^ gmul(C[2], s[2][c]) ^ gmul(C[3], s[3][c])
        o[1][c] = gmul(C[3], s[0][c]) ^ gmul(C[0], s[1][c]) ^ gmul(C[1], s[2][c]) ^ gmul(C[2], s[3][c])
        o[2][c] = gmul(C[2], s[0][c]) ^ gmul(C[3], s[1][c]) ^ gmul(C[0], s[2][c]) ^ gmul(C[1], s[3][c])
        o[3][c] = gmul(C[1], s[0][c]) ^ gmul(C[2], s[1][c]) ^ gmul(C[3], s[2][c]) ^ gmul(C[0], s[3][c])
    return o


def enc(pt_hex, key_hex):
    rk = gen_keys(key_hex)
    st = bxor(bytes.fromhex(pt_hex), bytes.fromhex(rk[0])).hex()
    for i in range(1, 10):
        st = from_mat(mix(shift(to_mat(st))))
        st = bxor(bytes.fromhex(st), bytes.fromhex(rk[i])).hex()
    st = from_mat(shift(to_mat(st)))
    return bxor(bytes.fromhex(st), bytes.fromhex(rk[10])).hex()


def dec(ct_hex, key_hex):
    rk = gen_keys(key_hex)
    st = to_mat(bxor(bytes.fromhex(ct_hex), bytes.fromhex(rk[10])).hex())
    st = shift(st, True)
    for i in range(9, 0, -1):
        st = to_mat(bxor(bytes.fromhex(from_mat(st)), bytes.fromhex(rk[i])).hex())
        st = shift(mix(st, True), True)
    return bxor(bytes.fromhex(from_mat(st)), bytes.fromhex(rk[0])).hex()


def solve(pt1, ct1, ct2):
    zero = "00" * 32
    fk = bxor(bytes.fromhex(ct1), bytes.fromhex(enc(pt1, zero))).hex()
    flag_hex = dec(bxor(bytes.fromhex(ct2), bytes.fromhex(fk)).hex(), zero)
    return bytes.fromhex(flag_hex).decode()


if __name__ == "__main__":
    if len(sys.argv) == 4:
        print(solve(*sys.argv[1:4]))
    else:
        lines = open("c701/output.txt").read().split()
        print(solve("72616e646f6d64617461313131313131", lines[0], lines[1]))
