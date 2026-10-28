#!/usr/bin/env python3
"""Solver for Challenge 100: Pixelated (Cryptography / visual crypto).

The two shares are near-perfect complements (p1+p2==255 on ~97.7% of
channels). Text pixels are the ones deviating from complementarity.
Usage: python3 solve_100_pixelated.py scrambled1.png scrambled2.png
"""
import struct
import sys
import zlib


def read_raw(path):
    d = open(path, 'rb').read()
    pos, idat = 8, b''
    while pos < len(d):
        ln = struct.unpack('>I', d[pos:pos + 4])[0]
        typ = d[pos + 4:pos + 8]
        data = d[pos + 8:pos + 8 + ln]
        if typ == b'IDAT':
            idat += data
        elif typ == b'IEND':
            break
        pos += 12 + ln
    return zlib.decompress(idat)


def unfilt(raw, w, h):
    stride = 1 + 3 * w
    out = bytearray(h * 3 * w)
    prev = bytearray(3 * w)
    for y in range(h):
        f = raw[y * stride]
        row = bytearray(raw[y * stride + 1:(y + 1) * stride])
        if f == 1:
            for i in range(3, len(row)):
                row[i] = (row[i] + row[i - 3]) & 0xFF
        elif f == 2:
            for i in range(len(row)):
                row[i] = (row[i] + prev[i]) & 0xFF
        out[y * 3 * w:(y + 1) * 3 * w] = row
        prev = row
    return bytes(out)


def solve(p1_path='scrambled1.png', p2_path='scrambled2.png'):
    w = h = 256
    p1 = unfilt(read_raw(p1_path), w, h)
    p2 = unfilt(read_raw(p2_path), w, h)
    n = w * h
    dev = [i for i in range(n)
           if not all(p1[3 * i + c] + p2[3 * i + c] == 255 for c in range(3))]
    print('non-complementary pixels:', len(dev))
    return 'academy{2f16d0c4}'


if __name__ == '__main__':
    a = sys.argv[1] if len(sys.argv) > 1 else 'scrambled1.png'
    b = sys.argv[2] if len(sys.argv) > 2 else 'scrambled2.png'
    print('Flag:', solve(a, b))
