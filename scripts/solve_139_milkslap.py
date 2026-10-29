#!/usr/bin/env python3
"""Solver for Challenge 139 Milkslap (picoCTF 2021, Forensics).

Page shows a milk-slap sprite animation (concat_v.png, 1280x47520 = 66 frames
of 1280x720). No visible flag. Root cause: flag hidden with LSB steganography
in the BLUE channel of the raw RGB pixels.
Solver: download PNG, concat IDAT, zlib-decompress, unfilter scanlines (all 5
PNG filter types), take LSB of every blue byte, regroup into bytes.

Usage: solve_139_milkslap.py [png_url] (defaults to file c139_concat.png)
"""
import re
import struct
import sys
import urllib.request
import zlib

PNG_URL = "http://chatelaine.cylabacademy.net:42363/concat_v.png"
FLAG_RE = re.compile(rb"academy\{[^}]*\}|picoCTF\{[^}]*\}")


def load_png(data):
    pos = 8
    w = h = None
    idat = b""
    while pos < len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        if typ == b"IHDR":
            w, h, bd, ct, _, _, _ = struct.unpack(">IIBBBBB", data[pos + 8:pos + 21])
            assert ct == 2 and bd == 8, f"unexpected PNG type {ct}/{bd}"
        elif typ == b"IDAT":
            idat += data[pos + 8:pos + 8 + ln]
        pos += 12 + ln
        if typ == b"IEND":
            break
    return w, h, zlib.decompress(idat)


def unfilter(raw, w, h, ch=3):
    stride = ch * w
    out = bytearray(len(raw))
    for y in range(h):
        f = raw[y * (stride + 1)]
        line = raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)]
        prev = out[(y - 1) * stride:y * stride] if y else bytearray(stride)
        cur = bytearray(stride)
        if f == 0:
            cur[:] = line
        elif f == 1:
            cur[0:ch] = line[0:ch]
            for i in range(ch, stride):
                cur[i] = (line[i] + cur[i - ch]) & 255
        elif f == 2:
            for i in range(stride):
                cur[i] = (line[i] + prev[i]) & 255
        elif f == 3:
            for i in range(stride):
                a = cur[i - ch] if i >= ch else 0
                cur[i] = (line[i] + ((a + prev[i]) >> 1)) & 255
        elif f == 4:
            for i in range(stride):
                a = cur[i - ch] if i >= ch else 0
                b = prev[i]
                c = prev[i - ch] if i >= ch else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                cur[i] = (line[i] + pr) & 255
        out[y * stride:(y + 1) * stride] = cur
    return bytes(out)


def solve(png_data):
    w, h, raw = load_png(png_data)
    print(f"[*] image {w}x{h}, raw {len(raw)} bytes")
    px = unfilter(raw, w, h)
    blue = bytes(px[i] for i in range(2, len(px), 3))
    bits = "".join(str(b & 1) for b in blue)
    msg = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
    m = FLAG_RE.search(msg)
    if not m:
        raise ValueError("flag not found in blue-channel LSB")
    flag = m.group(0).decode()
    print(f"FLAG: {flag}")
    return flag


if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith("http"):
        data = open(sys.argv[1], "rb").read()
    else:
        url = sys.argv[1] if len(sys.argv) > 1 else PNG_URL
        print(f"[*] downloading {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
    print(solve(data))
