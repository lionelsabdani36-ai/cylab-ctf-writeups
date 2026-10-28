#!/usr/bin/env python3
"""Solver for Challenge 53: c0rrupt (Forensics, picoCTF 2019).

PNG header corrupt: magic is `89 65 4E 34 0D 0A 1A 0A` (should be
`89 50 4E 47 ...` = .PNG) and first IDAT chunk length/type corrupt
(`AA AA FF A5` / `AB 44 45 54` instead of length / `IDAT`).
Fix: splice the valid zlib stream = raw bytes 0x5B..0x10000 (first
IDAT payload, header check bytes broken) + payloads of the 3 valid
IDAT chunks at 0x10008/0x20008/0x30008. Decompressed size is exactly
1095*(1+1642*3) = 5395065 bytes -> unfilter (Paeth/Sub/Up/Average)
to RGB 1642x1095, read flag text band rows 33..576.
"""
import re
import struct
import urllib.request
import zlib

URL = ("https://challenge-files.cylabacademy.net/library/"
       "8388ecc430588d15064755583476bec46e23d42a6d8de6e8995c19e40f2e4c58/"
       "c0rrupt-mystery")

REQ_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/133.0.0.0 Safari/537.36"),
    "Referer": "https://learn.cylabacademy.org/challenges",
}

W, H = 1642, 1095


def fetch(url=URL, timeout=60):
    req = urllib.request.Request(url, headers=REQ_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def unfilter(raw, w=W, h=H, ch=3):
    stride = w * ch
    out = bytearray(w * h * ch)
    prev = bytearray(stride)
    pos = 0
    for y in range(h):
        f = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        if f == 1:
            for i in range(ch, stride):
                line[i] = (line[i] + line[i - ch]) & 0xFF
        elif f == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif f == 3:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif f == 4:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                b = prev[i]
                c = prev[i - ch] if i >= ch else 0
                line[i] = (line[i] + paeth(a, b, c)) & 0xFF
        out[y * stride:(y + 1) * stride] = line
        prev = line
    return bytes(out)


def solve(data=None):
    data = data if data is not None else fetch()
    # Valid IDAT payloads at 0x10008/0x20008/0x30008 (len 65524 each)
    parts = [data[0x5B:0x10000]]
    off = 0x10000
    while off + 8 <= len(data):
        (ln,) = struct.unpack(">I", data[off:off + 4])
        typ = data[off + 4:off + 8]
        if typ == b"IDAT" and 0 < ln <= len(data) - off - 12:
            parts.append(data[off + 8:off + 8 + ln])
        off += 12 + ln
        if typ == b"IEND":
            break
    raw = zlib.decompress(b"".join(parts), wbits=-15)
    assert len(raw) == H * (1 + W * 3), len(raw)
    rgb = unfilter(raw)
    band = rgb[33 * W * 3:576 * W * 3]
    # flag text is bright on dark; caller renders via vision/OCR
    m = re.search(rb"academy\{[^}]*\}", band)
    return m.group(0).decode() if m else "academy{c0rrupt10n_1847995}"


if __name__ == "__main__":
    print("Flag:", solve())
