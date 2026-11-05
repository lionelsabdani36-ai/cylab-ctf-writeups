#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 286: Packets Primer (picoCTF 2022)
Category: Forensics / Network Traffic Analysis & Packet Dissection
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.1: Network Sniffing & Traffic Analysis)
CWE: CWE-319 (Cleartext Transmission of Sensitive Information)

Description:
Download the packet capture file and use packet analysis software to find the flag.
- network-dump.flag.pcap

Methodology:
- Libpcap format (magic 0xd4c3b2a1, little-endian) stores packet frames with timestamps and wire lengths.
- Dissection of Ethernet II, IPv4 (Protocol 6 / TCP), and TCP stream segments:
  Packet 4 captures a TCP payload sent from 10.0.2.15:48750 to 10.0.2.4:9000.
- Payload data contains spaced ASCII text:
  "a c a d e m y { p 4 c k 3 7 _ 5 h 4 r k _ 7 f f 5 a 1 b 3 }\\n"
- Stripping interplanetary whitespace normalizes the token to:
  academy{p4ck37_5h4rk_7ff5a1b3}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import struct
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/bf6ce90b17a773e3381a0b32b3bc624a0c8818e09346f5cee59e9fc66088934a/network-dump.flag.pcap"
EXPECTED_FLAG = "academy{p4ck37_5h4rk_7ff5a1b3}"


def parse_pcap_payloads(raw_data: bytes) -> list[bytes]:
    """Parse raw TCP payloads from standard libpcap format without external dependencies."""
    if len(raw_data) < 24:
        return []
    magic = raw_data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") else ">"

    payloads = []
    offset = 24
    while offset + 16 <= len(raw_data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f"{endian}IIII", raw_data[offset : offset + 16]
        )
        offset += 16
        if offset + incl_len > len(raw_data):
            break
        pkt = raw_data[offset : offset + incl_len]
        offset += incl_len

        # Parse Ethernet II header (14 bytes)
        if len(pkt) < 14:
            continue
        eth_type = struct.unpack("!H", pkt[12:14])[0]
        if eth_type == 0x0800:  # IPv4
            ip_hdr = pkt[14:]
            if len(ip_hdr) < 20:
                continue
            ip_ihl = (ip_hdr[0] & 0x0F) * 4
            ip_proto = ip_hdr[9]
            if ip_proto == 6:  # TCP
                tcp_hdr = ip_hdr[ip_ihl:]
                if len(tcp_hdr) >= 20:
                    tcp_offset = ((tcp_hdr[12] >> 4) & 0x0F) * 4
                    tcp_data = tcp_hdr[tcp_offset:]
                    if tcp_data:
                        payloads.append(tcp_data)
    return payloads


def solve(file_path: str | None = None) -> str:
    data = b""
    if file_path and os.path.exists(file_path):
        with open(file_path, "rb") as f:
            data = f.read()
    elif os.path.exists("network-dump.flag.pcap"):
        with open("network-dump.flag.pcap", "rb") as f:
            data = f.read()
    else:
        req = urllib.request.Request(
            ASSET_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://learn.cylabacademy.org/challenges",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()

    # Dissect TCP payloads
    payloads = parse_pcap_payloads(data)
    combined = b"".join(payloads)

    # Search for flag pattern (with or without spaces)
    m = re.search(
        rb"(?:a\s*c\s*a\s*d\s*e\s*m\s*y|p\s*i\s*c\s*o\s*C\s*T\s*F)\s*\{[^}]+\}",
        combined if combined else data,
    )
    if not m:
        # Fallback search across whole raw pcap bytes
        m = re.search(
            rb"(?:a\s*c\s*a\s*d\s*e\s*m\s*y|p\s*i\s*c\s*o\s*C\s*T\s*F)\s*\{[^}]+\}",
            data,
        )

    if not m:
        raise ValueError("Failed to locate flag token in PCAP packet payload")

    flag_raw = m.group(0).decode("latin-1")
    flag = "".join(flag_raw.split())

    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
