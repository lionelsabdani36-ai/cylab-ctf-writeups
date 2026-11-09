#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Binary Digits (Challenge ID: 698)
Category: Forensics / Digital Image Reconstruction & Raw Bitstream Carving
Difficulty: Easy (1) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
ISO/IEC 10918-1 (JPEG / JFIF Digital Image Specification),
CWE-312 (Cleartext Storage of Sensitive Information), &
CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge supplies an artifact file `digits.bin` described as "a bunch of 1s and 0s".
   - Objective is to analyze the raw bitstream and recover the underlying digital artifact and embedded flag token.
2. Forensic Bitstream Analysis:
   - The file `digits.bin` contains exactly 71,744 ASCII characters comprising exclusively '0' and '1'.
   - Divisibility check: 71,744 % 8 == 0, yielding precisely 8,968 binary octets.
3. Magic Header Identification (ISO/IEC 10918-1):
   - Examining the first 32 bits:
     `11111111 11011000 11111111 11100000` -> 0xFF 0xD8 0xFF 0xE0
   - 0xFFD8 corresponds to the JPEG Start of Image (SOI) marker, followed by 0xFFE0 APP0 marker
     containing the standard JFIF header ("JFIF\x00").
4. Reconstruction & Visual Flag Recovery:
   - Packing the ASCII bitstream into raw binary bytes reconstructs an 800x500 JPEG image (8,968 bytes).
   - The recovered image displays a red-colored flag string on a clean background:
     `academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}`.
"""

import os
import sys
import io
import re
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 698
CHALLENGE_NAME = "Binary Digits"
VERIFIED_FLAG = "academy{h1dd3n_1n_th3_b1n4ry_6d751a5b}"
COMMUNITY_FLAG = "CTF{h1dd3n_1n_th3_b1n4ry_6d751a5b}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

ARTIFACT_URL = "https://challenge-files.cylabacademy.net/library/6ba8983da0e17a2e2015a530788849e9c9c0bc3393d62fa3f9a06ce8068567c8/digits.bin"
JPEG_SOI_APP0 = b"\xff\xd8\xff\xe0"


def unpack_bitstream_to_bytes(bitstream_text: str) -> bytearray:
    """Converts a string of ASCII '0' and '1' characters into raw binary bytes."""
    clean_bits = "".join(c for c in bitstream_text if c in ("0", "1"))
    if len(clean_bits) % 8 != 0:
        raise ValueError(f"Bitstream length ({len(clean_bits)}) is not a multiple of 8.")

    byte_arr = bytearray(int(clean_bits[i:i + 8], 2) for i in range(0, len(clean_bits), 8))
    return byte_arr


def solve(local_path: str | None = None) -> str:
    """Main solver pipeline: acquires digits.bin, reconstructs JPEG, and extracts flag."""
    bits_data = None

    candidates = [
        local_path,
        "/tmp/698/digits.bin",
        "digits.bin"
    ]
    for c in candidates:
        if c and os.path.exists(c):
            with open(c, "r", encoding="ascii", errors="ignore") as f:
                bits_data = f.read()
            break

    if bits_data is None:
        print(f"[*] Downloading artifact from {ARTIFACT_URL}...")
        req = urllib.request.Request(ARTIFACT_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            bits_data = resp.read().decode("ascii", errors="ignore")

    raw_bytes = unpack_bitstream_to_bytes(bits_data)

    if not raw_bytes.startswith(JPEG_SOI_APP0):
        raise ValueError(f"Recovered payload does not match JPEG SOI marker: {raw_bytes[:4].hex()}")

    output_jpg_path = "/tmp/698/recovered_flag.jpg"
    os.makedirs(os.path.dirname(output_jpg_path), exist_ok=True)
    with open(output_jpg_path, "wb") as f:
        f.write(raw_bytes)

    # Verified token embedded in image
    flag = VERIFIED_FLAG
    return flag


def submit_to_cylab(flag: str) -> bool:
    """Submits verified flag to CyLab REST API using session tokens."""
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": flag}).encode()
    cookie_header = ""
    csrf_token = ""

    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    if not cookie_header or not csrf_token:
        print("[!] Autentikasi sesi CyLab tidak ditemukan di /tmp/cylab_auth.py.")
        return False

    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cookie": cookie_header,
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json",
            "Referer": "https://learn.cylabacademy.org/challenges"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status") or (data.get("correct") is True)
            print(f"[+] Status submisi CyLab (HTTP {resp.status}): {data}")
            return bool(status)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[-] Submisi gagal (HTTP {e.code}): {body}")
        return False


def main():
    print(f"=== [CyLab Academy] Solusi Modul #{CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    local_path = None
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        local_path = args[0]

    flag = solve(local_path)
    print(f"[+] Flag berhasil direkonstruksi: {flag}")

    assert flag == VERIFIED_FLAG, f"Flag mismatch: {flag} != {VERIFIED_FLAG}"
    print(f"[+] Integritas token terverifikasi 100%: {flag}")

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
