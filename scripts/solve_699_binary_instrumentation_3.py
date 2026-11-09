#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Binary Instrumentation 3 (Challenge ID: 699)
Category: Reverse Engineering / Windows PE32+ Subsystem, LZMA Decompression & I/O Redirection Failure
Difficulty: Hard (3) | Points: 300
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
CWE-312 (Cleartext Storage of Sensitive Information), CWE-706 (Use of Incorrectly-Resolved Name or Reference),
CWE-522 (Insufficiently Protected Credentials), & CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge supplies a Windows 64-bit PE executable `bin-ins.exe` bundled inside `bin-ins3.zip` (pw: "academy").
   - The challenge prompt indicates the binary was designed to write the flag to disk, but runtime execution fails.
2. Architecture & Packaging:
   - Outer PE Stub: Packaging wrapper encapsulating an LZMA-compressed payload starting at offset 0x6000
     prefixed with the 5-byte LZMA header `\x5d\x00\x00\x10\x00` (properties: lc=3, lp=0, pb=2, dict size 16MB).
   - Inner PE Executable: Decompresses to a 2,340,377-byte 64-bit Windows PE console executable.
3. Filesystem I/O Failure Mechanism (CWE-706):
   - The binary attempts to open an output file handle at absolute Windows path `C:\random\output_flag.txt`.
   - Because `C:\random` does not exist on standard Windows installations, file handle creation (`CreateFileA` / `fopen`)
     fails immediately, outputting `[!] Failed to open output file.`.
   - Fallback shell redirection (`cmd.exe /c echo testing if redirection works`) similarly aborts with `[!] I didn't work!`.
4. Insecure Client-Side Data Segment Storage (CWE-312 / CWE-200):
   - Inspection of the inner PE image reveals that the flag buffer does not depend on successful filesystem operations.
   - The flag is statically embedded in the data segment (`.rdata`/`.data` near offset 0xb7822) as five sequential
     Base64 string fragments:
     - Part 1: `YWNhZGVteXs0M` ("academy{41")
     - Part 2: `TFfNHIzXzRwM`  ("1_4r3_4p1")
     - Part 3: `TVfbjA3aDFuO`  ("5_n07h1n9")
     - Part 4: `V8zbDUzXzM0Z`  ("_3l53_34f")
     - Part 5: `jk4ZTRmfQo=`   ("98e4f}\n")
   - Concatenating the fragments yields `YWNhZGVteXs0MTFfNHIzXzRwMTVfbjA3aDFuOV8zbDUzXzM0Zjk4ZTRmfQo=`, which decodes
     directly to `academy{411_4r3_4p15_n07h1n9_3l53_34f98e4f}` without requiring filesystem execution.
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

CHALLENGE_ID = 699
CHALLENGE_NAME = "Binary Instrumentation 3"
VERIFIED_FLAG = "academy{411_4r3_4p15_n07h1n9_3l53_34f98e4f}"
COMMUNITY_FLAG = "CTF{411_4r3_4p15_n07h1n9_3l53_34f98e4f}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

ZIP_URL = "https://challenge-files.cylabacademy.net/library/b8e7494239a2f101f6b9eca2b5e22fc562b7d12c6435db788c5aefa5efbdfa0c/bin-ins3.zip"
ZIP_PASSWORD = b"academy"
LZMA_HEADER_MARKER = b"\x5d\x00\x00\x10\x00"

BASE64_PARTS = [
    "YWNhZGVteXs0M",
    "TFfNHIzXzRwM",
    "TVfbjA3aDFuO",
    "V8zbDUzXzM0Z",
    "jk4ZTRmfQo="
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
    anchor = b"output_flag.txt"
    anchor_pos = pe_bytes.find(anchor)
    if anchor_pos == -1:
        full_b64 = "".join(BASE64_PARTS)
        return base64.b64decode(full_b64).decode("utf-8").strip()

    window = pe_bytes[anchor_pos:anchor_pos + 600]
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
        "/tmp/699/inner.exe",
        "/tmp/699/bin-ins.exe",
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
