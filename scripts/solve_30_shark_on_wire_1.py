#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 30: shark on wire 1 (picoCTF 2019)
Category: Forensics / Network PCAP Packet Dissection & UDP Stream Tracking
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.1: Network Discovery & Protocol Inspection)
CWE: CWE-319 (Cleartext Transmission of Sensitive Information)

Description:
We found this packet capture. Recover the flag.
- Asset: shark-on-wire-1-capture.pcap

Methodology:
- Libpcap / PCAP capture format stores packet frames with timestamps, packet lengths, and link-layer data.
- The capture contains diverse UDP traffic (SSDP, mDNS, LLMNR, and synthetic point-to-point UDP traffic).
- Penyerang/pengirim mendistribusikan datagram UDP antar pasangan IP lokal pada jaringan 10.0.0.0/24:
  - Stream ke 10.0.0.13:8888 berisi decoy flag 'academy{N0t_a_fLag}'
  - Stream ke 10.0.0.12:8888 (UDP stream 6 pada Wireshark) berisi flag yang valid:
    'academy{StaT31355_636f6e6e}'
- Parser mengekstrak seluruh datagram UDP IPv4, mengelompokkan payload berdasarkan 4-tuple (src_ip, sport, dst_ip, dport),
  dan memulihkan flag resmi.

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import io
import os
import re
import struct
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/e64f2c2aaf9bf531af7be1787c1407c47a4cc7b57f251d5108a1151e9721a2d6/shark-on-wire-1-capture.pcap"
EXPECTED_FLAG = "academy{StaT31355_636f6e6e}"


def parse_pcap(pcap_bytes: bytes) -> dict[tuple[str, int, str, int], list[bytes]]:
    if len(pcap_bytes) < 24:
        raise ValueError("Invalid PCAP file: header too short")

    magic = pcap_bytes[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError(f"Unknown PCAP magic: {magic.hex()}")

    offset = 24
    streams: dict[tuple[str, int, str, int], list[bytes]] = {}

    while offset + 16 <= len(pcap_bytes):
        _, _, incl_len, _ = struct.unpack(endian + "IIII", pcap_bytes[offset:offset+16])
        offset += 16
        if offset + incl_len > len(pcap_bytes):
            break
        pkt_data = pcap_bytes[offset:offset+incl_len]
        offset += incl_len

        # Ethernet frame header: 14 bytes
        if len(pkt_data) < 14:
            continue
        eth_type = struct.unpack("!H", pkt_data[12:14])[0]
        if eth_type != 0x0800:  # Only IPv4
            continue

        ip_data = pkt_data[14:]
        if len(ip_data) < 20:
            continue
        ihl = (ip_data[0] & 0x0F) * 4
        proto = ip_data[9]
        src_ip = ".".join(str(b) for b in ip_data[12:16])
        dst_ip = ".".join(str(b) for b in ip_data[16:20])

        if proto == 17:  # UDP protocol
            udp_data = ip_data[ihl:]
            if len(udp_data) < 8:
                continue
            sport, dport, length, _ = struct.unpack("!HHHH", udp_data[:8])
            payload = udp_data[8:length]
            if payload:
                key = (src_ip, sport, dst_ip, dport)
                streams.setdefault(key, []).append(payload)

    return streams


def solve(file_path: str | None = None) -> str:
    if file_path and os.path.exists(file_path):
        with open(file_path, "rb") as f:
            pcap = f.read()
    elif os.path.exists("shark-on-wire-1-capture.pcap"):
        with open("shark-on-wire-1-capture.pcap", "rb") as f:
            pcap = f.read()
    else:
        req = urllib.request.Request(
            ASSET_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://learn.cylabacademy.org/challenges",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            pcap = resp.read()

    streams = parse_pcap(pcap)

    # Collect flags across all UDP streams
    valid_flag = None
    for key, payloads in streams.items():
        combined = b"".join(payloads)
        matches = re.findall(rb"(?:academy|picoCTF)\{[^}]+\}", combined)
        for m in matches:
            text_flag = m.decode("latin1", errors="ignore")
            # Filter out known decoy flag
            if "N0t_a_fLag" not in text_flag:
                valid_flag = text_flag
                break
        if valid_flag:
            break

    if not valid_flag:
        raise ValueError("Failed to recover valid flag from PCAP UDP streams")

    assert valid_flag == EXPECTED_FLAG, f"Flag mismatch: {valid_flag} != {EXPECTED_FLAG}"
    return valid_flag


if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target_file)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
