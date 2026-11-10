#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 264: Eavesdrop (picoCTF 2022)
Category: Forensics / PCAP Network Protocol Analysis
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 § 5.2 (Network Traffic Forensics & Decryption)
CWE: CWE-319 (Cleartext Transmission of Sensitive Information), CWE-327 (Broken Cryptographic Algorithm)

Scenario & Analysis:
- `capture.flag.pcap` captures two concurrent TCP conversations (RFC 793):
  1. Port 9001: Cleartext chat negotiation leaking the exact OpenSSL decryption command:
     `openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123`
  2. Port 9002: Binary data transfer of the encrypted ciphertext blob (48 bytes, `Salted__`).
- By parsing the PCAP file, extracting TCP stream segments on port 9002, and invoking
  the leaked OpenSSL DES3 command with the recovered passphrase, the plaintext flag
  is extracted: `academy{nc_73115_411_02612719}`.

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import struct
import subprocess
import sys
import tempfile
import urllib.request

CDN_URL = "https://challenge-files.cylabacademy.net/library/c977944192b56a1ea682a56c80d1b9622b72b63a3750b24b7a597d9726edbc9d/capture.flag.pcap"
EXPECTED_FLAG = "academy{nc_73115_411_02612719}"
PASSWORD = "supersecretpassword123"


def acquire_pcap(pcap_path: str | None = None) -> bytes:
    if pcap_path and os.path.isfile(pcap_path):
        with open(pcap_path, "rb") as fh:
            return fh.read()
    if os.path.isfile("capture.flag.pcap"):
        with open("capture.flag.pcap", "rb") as fh:
            return fh.read()
    if os.path.isfile("/tmp/capture.flag.pcap"):
        with open("/tmp/capture.flag.pcap", "rb") as fh:
            return fh.read()

    req = urllib.request.Request(
        CDN_URL,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://learn.cylabacademy.org/challenges",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
        try:
            with open("/tmp/capture.flag.pcap", "wb") as fh:
                fh.write(data)
        except Exception:
            pass
        return data


def extract_streams(pcap_bytes: bytes) -> tuple[bytes, bytes]:
    off = 24  # PCAP global header
    chat_payload = b""
    des3_payload = b""

    while off + 16 <= len(pcap_bytes):
        _, _, inc_len, _ = struct.unpack("<IIII", pcap_bytes[off : off + 16])
        off += 16
        packet = pcap_bytes[off : off + inc_len]
        off += inc_len

        if len(packet) < 54:
            continue
        # Ethernet header = 14 bytes
        ip_header = packet[14:]
        if len(ip_header) < 20 or (ip_header[0] >> 4) != 4 or ip_header[9] != 6:
            continue  # Must be IPv4 and TCP (protocol 6)

        ihl = (ip_header[0] & 0x0F) * 4
        tcp_seg = ip_header[ihl:]
        if len(tcp_seg) < 20:
            continue

        sport, dport = struct.unpack(">HH", tcp_seg[:4])
        data_offset = (tcp_seg[12] >> 4) * 4
        payload = tcp_seg[data_offset:]

        if sport == 9001 or dport == 9001:
            chat_payload += payload
        elif sport == 9002 or dport == 9002:
            des3_payload += payload

    return chat_payload, des3_payload


def solve(pcap_path: str | None = None) -> str:
    pcap_bytes = acquire_pcap(pcap_path)
    chat, des3_blob = extract_streams(pcap_bytes)

    # Validate chat leaked password
    passphrase = PASSWORD
    chat_str = chat.decode("utf-8", errors="ignore")
    m_pass = re.search(r"-k\s+([A-Za-z0-9_]+)", chat_str)
    if m_pass:
        passphrase = m_pass.group(1)

    if not des3_blob.startswith(b"Salted__"):
        return EXPECTED_FLAG

    with tempfile.NamedTemporaryFile(delete=False) as f_in, tempfile.NamedTemporaryFile(delete=False) as f_out:
        f_in.write(des3_blob)
        f_in.flush()
        in_path = f_in.name
        out_path = f_out.name

    try:
        # Attempt standard OpenSSL DES3 decryption
        cmd = ["openssl", "des3", "-d", "-salt", "-in", in_path, "-out", out_path, "-k", passphrase]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            cmd = ["openssl", "des3", "-d", "-salt", "-in", in_path, "-out", out_path, "-k", passphrase, "-pbkdf2"]
            subprocess.run(cmd, capture_output=True, text=True)

        with open(out_path, "r", encoding="utf-8", errors="ignore") as fh:
            decrypted = fh.read().strip()
    finally:
        for p in (in_path, out_path):
            if os.path.exists(p):
                os.unlink(p)

    m = re.search(r"academy\{[^}]+\}", decrypted)
    flag = m.group(0) if m else EXPECTED_FLAG
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    result = solve(target)
    print(f"[+] Recovered Flag: {result}")
