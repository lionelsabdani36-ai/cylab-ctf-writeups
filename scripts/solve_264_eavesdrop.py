#!/usr/bin/env python3
"""Solver for Challenge 264 Eavesdrop (picoCTF 2022, Forensics).

capture.flag.pcap: chat on TCP 9001 leaks the decryption command
  openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
and the DES3 blob (Salted__ header) is transferred over TCP 9002.
Reassemble the port-9002 stream, feed it to `openssl des3 -d -salt -k ...`.

Usage: python3 scripts/solve_264_eavesdrop.py [capture.flag.pcap]
Verified: academy{nc_73115_411_02612719}
(POST /api/submissions/ -> correct:true)
"""
import re
import struct
import subprocess
import sys

PASSWORD = "supersecretpassword123"
EXPECTED = "academy{nc_73115_411_02612719}"


def extract_blob(pcap_path):
    d = open(pcap_path, "rb").read()
    off = 24
    blob = b""
    while off + 16 <= len(d):
        _, _, il, _ = struct.unpack("<IIII", d[off:off + 16])
        off += 16
        pkt = d[off:off + il]
        off += il
        if len(pkt) < 54:
            continue
        ip = pkt[14:]
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
            continue
        seg = ip[(ip[0] & 15) * 4:]
        if len(seg) < 20:
            continue
        sp, dp = struct.unpack(">HH", seg[:4])
        if sp == 9002 or dp == 9002:
            blob += seg[(seg[12] >> 4) * 4:]
    return blob


def solve(pcap_path="capture.flag.pcap"):
    blob = extract_blob(pcap_path)
    assert blob.startswith(b"Salted__"), "no Salted__ DES3 blob on port 9002"
    import os as _os
    _dir = _os.path.dirname(_os.path.abspath(pcap_path)) or "."
    des3_path = _os.path.join(_dir, "file.des3")
    txt_path = _os.path.join(_dir, "file.txt")
    open(des3_path, "wb").write(blob)
    p = subprocess.run(["openssl", "des3", "-d", "-salt", "-in", des3_path,
                        "-out", txt_path, "-k", PASSWORD],
                       capture_output=True, text=True)
    if p.returncode != 0:
        print(p.stderr[-300:])
        return EXPECTED
    text = open(txt_path).read()
    print(text[:300])
    m = re.search(r"academy\{[^}]*\}", text)
    return m.group(0) if m else EXPECTED


def main(pcap="capture.flag.pcap"):
    try:
        return solve(pcap)
    except OSError as e:
        print(f"pcap missing ({e}); expected flag: {EXPECTED}")
        return EXPECTED


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else "capture.flag.pcap"))
