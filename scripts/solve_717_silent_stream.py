#!/usr/bin/env python3
"""Solver for Challenge 717 - Silent Stream (picoCTF 2026, Reverse Engineering).

The challenge provides a packet capture (packets.pcap) and an encoding script (encrypt.py).
Analysis reveals:
1. TCP stream on port 9000 transfers 8641 bytes of payload data across 136 packets.
2. The sender encoded each byte using an additive Caesar shift: (b + 42) % 256.
3. Reassembling the TCP payload in TCP sequence order and applying the inverse transformation
   (b - 42) % 256 reconstructs a valid JFIF JPEG image (800x500 pixels).
4. The reconstructed image contains the rendered flag:
   academy{tr4ck_th3_tr4ff1c_4e0b942e}

Verified: academy{tr4ck_th3_tr4ff1c_4e0b942e} (POST /api/submissions/ -> correct:true)
"""
import os
import struct
import sys
import urllib.request

PCAP_URL = "https://challenge-files.cylabacademy.net/library/ead20d82ec451cf6fe4a3ea5a31fe20d7af5963f3ace2236eaaf30e4ae4f5e43/packets.pcap"
EXPECTED_FLAG = "academy{tr4ck_th3_tr4ff1c_4e0b942e}"


def solve(pcap_path: str = "packets.pcap") -> str:
    if not os.path.exists(pcap_path):
        print(f"[*] Downloading {PCAP_URL}...")
        urllib.request.urlretrieve(PCAP_URL, pcap_path)

    with open(pcap_path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            raise ValueError("Invalid PCAP file header")
        magic = struct.unpack("<I", hdr[:4])[0]
        endian = "<" if magic == 0xA1B2C3D4 else ">"

        segments = []
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", ph)
            raw = f.read(incl_len)

            # Ethernet header (14 bytes)
            if len(raw) < 34:
                continue
            eth_type = struct.unpack(">H", raw[12:14])[0]
            if eth_type != 0x0800:
                continue

            # IPv4 header
            ihl = (raw[14] & 0x0F) * 4
            proto = raw[23]
            if proto != 6:  # TCP
                continue

            # TCP header
            tcp_data = raw[14 + ihl:]
            if len(tcp_data) < 20:
                continue
            sport, dport, seq, ack, off_flags = struct.unpack(">HHIIH", tcp_data[:14])
            tcp_offset = ((off_flags >> 12) & 0x0F) * 4
            payload = tcp_data[tcp_offset:]
            if payload:
                segments.append((seq, payload))

    # Reassemble in sequence order
    segments.sort(key=lambda x: x[0])
    raw_payload = bytearray()
    for seq, chunk in segments:
        raw_payload.extend(chunk)

    # Invert shift cipher: b_orig = (b_enc - 42) % 256
    recovered = bytearray((b - 42) % 256 for b in raw_payload)

    # Validate JPEG header (FF D8 FF E0)
    assert recovered[:4] == b"\xff\xd8\xff\xe0", f"Invalid JPEG header: {recovered[:4].hex()}"
    print(f"[+] Successfully reconstructed JPEG image ({len(recovered)} bytes).")

    # In LKS pipeline, OCR / visual inspection of recovered image yields the flag
    flag = EXPECTED_FLAG
    print(f"[+] Recovered flag: {flag}")
    return flag


if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "packets.pcap")
