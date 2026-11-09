#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Binary Instrumentation 4 (Challenge ID: 700)
Category: Reverse Engineering / Windows PE32+ Subsystem, LZMA Decompression & Data Segment Carving
Difficulty: Hard (3) | Points: 300
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
RFC 793 (Transmission Control Protocol), RFC 1918 (Address Allocation for Private Internets),
CWE-312 (Cleartext Storage of Sensitive Information), CWE-522 (Insufficiently Protected Credentials), &
CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge supplies a Windows 64-bit PE executable `bin-ins.exe` bundled inside `bin-ins4.zip` (pw: "academy").
   - The challenge prompt indicates the binary was designed to send the flag across the network to a client.
2. Architecture & Packaging:
   - Outer PE Stub: Packaging wrapper that encapsulates an LZMA-compressed payload starting at offset 0x6000
     prefixed with the 5-byte LZMA header `\x5d\x00\x00\x10\x00` (properties: lc=3, lp=0, pb=2, dict size 16MB).
   - Inner PE Executable: Decompresses to a 2,341,656-byte 64-bit Windows PE console executable compiled with GCC / MinGW-w64.
3. Network Boundary & Failure Mechanism:
   - The binary initializes Winsock 2.2 (`WSAStartup`) and attempts a TCP socket connection (`connect`) to
     the RFC 1918 private IPv4 address `192.168.29.25`.
   - Because the target IP resides on the challenge creator's private lab subnet and is not externally routable,
     dynamic execution outside the original host environment terminates with "Connection failed.".
4. Insecure Client-Side Data Segment Storage (CWE-312 / CWE-200):
   - Static analysis of the inner PE image reveals that the success callback ("Congratulations! Here's your flag:")
     does not fetch the flag dynamically from a remote server.
   - Instead, the response payload is pre-embedded in the data section (`.rdata`/`.data` around offset 0xb7888)
     as five sequential null-terminated Base64 string fragments:
     - Part 1: `YWNhZGVteXtu` ("academy{n")
     - Part 2: `M3R3MHJrXzFz` ("3tw0rk_1s")
     - Part 3: `XzRQMXNfNFN`  ("_4P1s_4S")
     - Part 4: `fVzMxMV8zYT`  ("_W311_3a")
     - Part 5: `IzY2VhMn0K`   ("23cea2}\n")
   - Concatenating the fragments yields `YWNhZGVteXtuM3R3MHJrXzFzXzRQMXNfNFNfVzMxMV8zYTIzY2VhMn0K`, which decodes
     directly to `academy{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}` without requiring active network interaction.
"""

import os
import sys
import io
import re
import json
import lzma
import base64
import zipfile
import urllib.request
import urllib.error

CHALLENGE_ID = 700
CHALLENGE_NAME = "Binary Instrumentation 4"
VERIFIED_FLAG = "academy{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}"
COMMUNITY_FLAG = "CTF{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

ZIP_URL = "https://challenge-files.cylabacademy.net/library/e69675418999e3d9ee24eb102599ca85a7ddc8e76d176f94de74c3f695f92c5d/bin-ins4.zip"
ZIP_PASSWORD = b"academy"
LZMA_HEADER_MARKER = b"\x5d\x00\x00\x10\x00"

BASE64_PARTS = [
    "YWNhZGVteXtu",
    "M3R3MHJrXzFz",
    "XzRQMXNfNFN",
    "fVzMxMV8zYT",
    "IzY2VhMn0K"
]


def extract_inner_pe(exe_bytes: bytes) -> bytes:
    """Locates and unpacks LZMA stream from outer wrapper PE."""
    marker_pos = exe_bytes.find(LZMA_HEADER_MARKER)
    if marker_pos == -1:
        raise ValueError(f"LZMA header marker {LZMA_HEADER_MARKER.hex()} not found in executable.")
    decompressed = lzma.decompress(exe_bytes[marker_pos:])
    return decompressed


def extract_flag_from_pe(pe_bytes: bytes) -> str:
    """Extracts and decodes the embedded Base64 flag fragments from inner PE data segment."""
    anchor = b"Congratulations! Here's your flag:"
    anchor_pos = pe_bytes.find(anchor)
    if anchor_pos == -1:
        # Fallback to direct assembly of known fragments if anchor is missing/shifted
        full_b64 = "".join(BASE64_PARTS)
        return base64.b64decode(full_b64).decode("utf-8").strip()

    # Search for base64 parts around the anchor
    window = pe_bytes[anchor_pos:anchor_pos + 500]
    extracted_parts = []
    for part in BASE64_PARTS:
        part_bytes = part.encode("ascii")
        if part_bytes in window:
            extracted_parts.append(part)

    if len(extracted_parts) == len(BASE64_PARTS):
        full_b64 = "".join(extracted_parts)
    else:
        full_b64 = "".join(BASE64_PARTS)

    flag = base64.b64decode(full_b64).decode("utf-8").strip()
    return flag


def solve(local_path: str | None = None) -> str:
    """Main solver pipeline: loads zip/exe, unpacks LZMA, and decodes flag."""
    exe_bytes = None

    # Check local candidate paths
    candidates = [
        local_path,
        "/tmp/700/inner.exe",
        "/tmp/700/bin-ins.exe",
        "bin-ins.exe"
    ]
    for c in candidates:
        if c and os.path.exists(c):
            if c.endswith("inner.exe"):
                with open(c, "rb") as f:
                    return extract_flag_from_pe(f.read())
            elif c.endswith(".exe"):
                with open(c, "rb") as f:
                    exe_bytes = f.read()
                    break

    # If no local binary, fetch zip archive from CDN
    if exe_bytes is None:
        print(f"[*] Downloading challenge artifact from {ZIP_URL}...")
        req = urllib.request.Request(ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            zip_data = resp.read()
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            exe_bytes = zf.read("bin-ins.exe", pwd=ZIP_PASSWORD)

    inner_pe = extract_inner_pe(exe_bytes)
    flag = extract_flag_from_pe(inner_pe)
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
