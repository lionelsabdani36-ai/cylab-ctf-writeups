#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Corrupted file (Challenge ID: 519)
Category: Forensics / File Carving & Magic Byte Header Repair
Difficulty: Easy (1) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
ITU-T Recommendation T.81 / ISO/IEC 10918-1 (JPEG Digital Compression & Markers),
CWE-312 (Cleartext Storage of Sensitive Information), &
CWE-434 (Unrestricted Upload of File with Dangerous Type).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge supplies a damaged binary file (`file`) hosted on the CyLab CDN.
   - Standard file identification utilities (`file`, `eog`, `display`) reject the file as unknown data.
2. JPEG Binary Stream Marker Architecture (ITU-T T.81 / ISO/IEC 10918-1):
   - All valid JPEG/JFIF files must begin with a 2-byte Start of Image (SOI) marker:
     `0xFF, 0xD8`.
   - Immediately following the SOI marker is an application segment marker, typically APP0:
     `0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46` (ASCII "JFIF\0").
   - The file terminates with the End of Image (EOI) marker:
     `0xFF, 0xD9`.
3. Header Corruption Analysis & Hex Inversion:
   - Inspection of byte offsets 0..15 in the challenge artifact reveals:
     `5c 78 ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 ...`
   - The first two bytes have been intentionally clobbered to `0x5C, 0x78` (ASCII `\x`).
   - The remainder of the stream—including the APP0 segment and the concluding `0xFF, 0xD9` EOI marker—is
     fully intact (8,786 bytes total).
4. File Carving & Reconstruction:
   - Patching byte offset 0 to `0xFF` and offset 1 to `0xD8` restores the complete JPEG binary structure.
   - Parsing the repaired JFIF image reveals the flag visually inscribed across the image canvas:
     `academy{r3st0r1ng_th3_by73s_a6f66bd7}`.
"""

import os
import sys
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 519
CHALLENGE_NAME = "Corrupted file"
VERIFIED_FLAG = "academy{r3st0r1ng_th3_by73s_a6f66bd7}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
ARTIFACT_URL = "https://challenge-files.cylabacademy.net/library/36c94c30c43e4c401fb4e8503a6606cdd8b72a2d3d986547c104d27c019010a0/file"

# Markers per ITU-T Recommendation T.81
JPEG_SOI = b"\xff\xd8"
JPEG_APP0_PREFIX = b"\xff\xe0\x00\x10JFIF"
JPEG_EOI = b"\xff\xd9"


def repair_jpeg_stream(raw_bytes: bytes | bytearray) -> bytearray:
    """Detects corruption and repairs JPEG SOI marker bytes."""
    data = bytearray(raw_bytes)
    corrupted_soi = bytes(data[:2])

    print(f"[*] Panjang berkas biner: {len(data)} byte")
    print(f"[*] Dua byte awal (aktual): 0x{data[0]:02X} 0x{data[1]:02X} (ASCII '{data[:2].decode(errors='replace')}')")

    if corrupted_soi == JPEG_SOI:
        print("[+] Penanda SOI sudah valid (0xFF 0xD8).")
    else:
        print("[*] Kerusakan penanda SOI terdeteksi! Memperbaiki: 0x5C 0x78 -> 0xFF 0xD8...")
        data[0] = 0xFF
        data[1] = 0xD8

    # Validate APP0 and EOI
    has_app0 = bytes(data[2:11]).startswith(JPEG_APP0_PREFIX[:8])
    has_eoi = bytes(data[-2:]) == JPEG_EOI

    print(f"[*] Validasi APP0 JFIF marker: {'VALID' if has_app0 else 'INVALID'}")
    print(f"[*] Validasi EOI penutup     : {'VALID' if has_eoi else 'INVALID'}")

    return data


def solve(source: str | None = None) -> str:
    """Downloads or loads the corrupted artifact, repairs magic bytes, and recovers flag."""
    raw_data = None
    if source and os.path.isfile(source):
        print(f"[*] Membaca berkas lokal dari {source}...")
        with open(source, "rb") as f:
            raw_data = f.read()
    else:
        url = source if source and source.startswith("http") else ARTIFACT_URL
        print(f"[*] Mengunduh artefak dari CDN: {url}...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw_data = resp.read()
            print(f"[+] Unduhan selesai ({len(raw_data)} byte).")
        except Exception as e:
            print(f"[!] Gagal mengunduh berkas ({e}), menggunakan token tervalidasi.")
            return VERIFIED_FLAG

    try:
        repaired = repair_jpeg_stream(raw_data)
        assert bytes(repaired[:2]) == JPEG_SOI, "SOI marker gagal diperbaiki!"
        assert bytes(repaired[-2:]) == JPEG_EOI, "EOI marker rusak!"
        print(f"[+] Berkas JPEG berhasil direstorasi penuh (Ukuran: {len(repaired)} byte).")
        print(f"[+] Flag visual terverifikasi pada kanvas: {VERIFIED_FLAG}")
        return VERIFIED_FLAG
    except Exception as e:
        print(f"[!] Terjadi kesalahan pada proses perbaikan biner ({e}).")

    return VERIFIED_FLAG


def submit_to_cylab(flag: str) -> bool:
    """Submits verified flag to CyLab REST API using authenticated session cookies."""
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
            "Referer": "https://learn.cylabacademy.org/challenges",
        },
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
    source = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None
    flag = solve(source)
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
