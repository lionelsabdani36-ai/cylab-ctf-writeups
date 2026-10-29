#!/usr/bin/env python3
"""Solver for Challenge 348 FindAndOpen (picoCTF 2023, Forensics).

dump.pcap contains fake Ethernet frames whose payload is ASCII. The frame
'AABBHHPJGTFRLK' + base64 decodes to 'This is the secret: academy{R34DING_LOKd_'
(the trailing prefix is the ZipCrypto password for flag.zip, NOT the flag).
Other streams ('Could the flag have been splitted?', '...other file',
'ababab...') are decoys. Unzip with that password -> flag file (45 bytes).

Usage: solve_348_findandopen.py [dump.pcap path] [flag.zip path]
Verified: academy{R34DING_LOKd_fil56_succ3ss_9989a41b} (POST /api/submissions/ -> correct:true)
"""
import base64
import struct
import sys
import zipfile

EXPECTED = "academy{R34DING_LOKd_fil56_succ3ss_9989a41b}"


def password_from_pcap(path: str) -> str:
    d = open(path, "rb").read()
    assert d[:4] == b"\xd4\xc3\xb2\xa1", "not a little-endian libpcap file"
    off = 24
    while off + 16 <= len(d):
        incl = struct.unpack("<I", d[off + 8:off + 12])[0]
        off += 16
        pkt = d[off:off + incl]
        off += incl
        try:
            s = pkt.decode("ascii")
        except UnicodeDecodeError:
            continue
        if "VGhpcyBpcyB0aGUgc2VjcmV0Oi" in s:
            b64 = s[s.index("VGhpcyBpcyB0aGUgc2VjcmV0Oi"):]
            plain = base64.b64decode(b64).decode()
            assert plain.startswith("This is the secret: "), plain
            return plain.split(": ", 1)[1]
    raise ValueError("password stream not found in pcap")


def solve(pcap: str = "dump.pcap", zippath: str = "flag.zip") -> str:
    pw = password_from_pcap(pcap)
    data = zipfile.ZipFile(zippath).read("flag", pwd=pw.encode()).decode()
    print("password:", pw)
    print("flag:", data.strip())
    assert data.strip() == EXPECTED, data
    return EXPECTED


if __name__ == "__main__":
    a = sys.argv[1:] + ["dump.pcap", "flag.zip"]
    print(solve(a[0], a[1]))
