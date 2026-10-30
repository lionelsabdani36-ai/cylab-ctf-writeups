#!/usr/bin/env python3
"""Solver for Challenge 268 File types (picoCTF 2022, Forensics).

Artifact: Flag.pdf is a GNU shar shell archive. Full nesting chain:
  shar -> uuencode -> BSD ar ("#1/" extended name) -> bzip2 -> gzip ->
  lzip -> LZ4 frame -> LZMA (ALONE) -> lzop -> lzip -> XZ -> hex text -> flag.
Hint: "some file types can contain and nest other files".

Needs external binaries for two stages: `lz4` and `lzop` (apt install lz4 lzop).
Everything else is stdlib. Verified end-to-end 2026-10-30.

Usage: solve_268_file_types.py <Flag.pdf path>
  Prints the academy{...} flag.
"""
import bz2
import gzip
import lzma
import re
import struct  # noqa
import subprocess
import sys
import tempfile
import os

LZMA1_4096 = [{'id': lzma.FILTER_LZMA1, 'dict_size': 1 << 12,
               'lc': 3, 'lp': 0, 'pb': 2}]


def uu_decode(body):
    out = bytearray()
    for line in body.split('\n'):
        line = line.rstrip('\r')
        if not line:
            continue
        n = (ord(line[0]) - 32) & 0x3F
        raw = line[1:]
        buf = bytearray()
        for i in range(0, len(raw), 4):
            chunk = raw[i:i + 4]
            if len(chunk) < 4:
                break
            c = [(ord(x) - 32) & 0x3F for x in chunk]
            buf.append((c[0] << 2) | (c[1] >> 4))
            buf.append(((c[1] & 15) << 4) | (c[2] >> 2))
            buf.append(((c[2] & 3) << 6) | c[3])
        out += buf[:n]
    return bytes(out)


def ar_member(data):
    """Parse plain SysV/GNU ar: 8-byte magic + 60-byte header, short 'name/'."""
    assert data[:8] == b'!<arch>\n', 'not ar archive'
    pos = 8
    name = data[pos:pos + 16].decode()
    size = int(data[pos + 48:pos + 58].decode().strip())
    assert data[pos + 58:pos + 60] == b'`\n', 'bad ar fmag'
    if name.startswith('#1/'):
        extlen = int(name[3:].strip())
        member = data[pos + 60:pos + 60 + size]
        fname = member[:extlen].rstrip(b'\0').decode()
        return fname, member[extlen:]
    return name.strip().rstrip('/'), data[pos + 60:pos + 60 + size]


def cpio_bin_extract(data):
    """Little-endian binary cpio (magic 070707 = bytes c7 71).

    26-byte header of LE 16-bit shorts:
      magic dev ino mode uid gid nlink rdev mtime[2] namesize filesize[2]
    where filesize = (w0 << 16) | w1. Filename follows (namesize bytes
    incl NUL), padded to even; then file data, padded to even.
    """
    import struct
    assert data[:2] == b'\xc7\x71', 'not binary cpio (070707)'
    f = struct.unpack('<13H', data[:26])
    assert f[0] == 0x71c7
    namesize, filesize = f[10], (f[11] << 16) | f[12]
    name = data[26:26 + namesize].rstrip(b'\0').decode()
    start = 26 + namesize
    if start % 2:
        start += 1
    return name, data[start:start + filesize]


def lzip_decode(d):
    assert d[:4] == b'LZIP' and d[4] == 1, 'not lzip'
    stream = d[6:-20]
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=list(LZMA1_4096))
    return bytes(dec.decompress(stream))


def ext_lz4(data):
    with tempfile.TemporaryDirectory() as td:
        inp = os.path.join(td, 'in')
        open(inp, 'wb').write(data)
        r = subprocess.run(['lz4', '-d', '-c', inp], check=True,
                           capture_output=True, timeout=60)
        return r.stdout


def ext_lzop(data):
    with tempfile.TemporaryDirectory() as td:
        inp = os.path.join(td, 'in.lzo')
        outp = os.path.join(td, 'out')
        open(inp, 'wb').write(data)
        subprocess.run(['lzop', '-d', '-o', outp, inp],
                       check=True, capture_output=True, timeout=60)
        return open(outp, 'rb').read()


def main():
    src = open(sys.argv[1] if len(sys.argv) > 1 else 'Flag.pdf',
               encoding='utf-8', errors='replace').read()
    m = re.search(r'^begin 600 flag\n(.*?)\nend', src, re.M | re.S)
    assert m, 'uuencoded body not found (shar archive?)'
    uu = uu_decode(m.group(1))
    fname, member = ar_member(uu)
    assert fname == 'flag', fname
    cname, cbz = cpio_bin_extract(member)
    assert cname == 'flag', cname
    assert cbz[:3] == b'BZh', 'stage: not bzip2'
    l3 = bz2.decompress(cbz)
    assert l3[:2] == b'\x1f\x8b', 'stage: not gzip'
    l4 = gzip.decompress(l3)
    assert l4[:4] == b'LZIP', 'stage: not lzip'
    l5 = lzip_decode(l4)
    assert l5[:4] == b'\x04\x22\x4d\x18', 'stage: not LZ4 frame'
    l6 = ext_lz4(l5)
    l7 = lzma.decompress(l6, format=lzma.FORMAT_ALONE)
    assert l7[:4] == b'\x89LZO', 'stage: not lzop'
    l8 = ext_lzop(l7)
    assert l8[:4] == b'LZIP', 'stage2: not lzip'
    l9 = lzip_decode(l8)
    l10 = lzma.decompress(l9, format=lzma.FORMAT_XZ)
    lines = [ln.strip() for ln in l10.decode().split() if ln.strip()]
    flag = ''.join(bytes.fromhex(ln).decode() for ln in lines)
    assert flag.startswith('academy{'), flag
    print(flag)


if __name__ == '__main__':
    main()
