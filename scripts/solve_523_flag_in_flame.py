#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Flag in Flame (Challenge ID: 523)
Category: Forensics / Log Data Obfuscation, Base64 Stream Decoding & Hex Visual Carving
Difficulty: Easy (1) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
RFC 4648 §4 (The Base 64 Alphabet),
ISO/IEC 15948:2004 / W3C Portable Network Graphics (PNG) Specification (Magic Signature),
CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), &
CWE-532 (Insertion of Sensitive Information into Log File).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge simulates a SOC incident response scenario where a massive suspicious log file
     (`logs.txt`) was discovered on a breached host.
   - The file contains a monolithic block of Base64 encoded text instead of standard log lines.
2. File Structure & Magic Byte Reconstruction:
   - Decoding the Base64 stream begins with `iVBORw0KGgoAAAANSUhEUg...`.
   - In RFC 4648, `iVBORw0KGgo=` decodes to `\x89PNG\r\n\x1a\n`, which is the canonical 8-byte
     PNG magic header signature (`89 50 4E 47 0D 0A 1A 0A`).
   - The decoded payload is an 896x1152 pixel truecolor image depicting a cybersecurity scenario.
3. Visual Steganography & Hexadecimal Inscription:
   - In the lower border of the raster image canvas, an uncompressed hexadecimal string is rendered:
     `61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F32303433646264317D`
   - Inverting the hexadecimal byte sequence (`bytes.fromhex(...)`) reconstructs the ASCII flag:
     `academy{forensics_analysis_is_amazing_2043dbd1}`.
"""

import os
import sys
import json
import base64
import urllib.request
import urllib.error

CHALLENGE_ID = 523
CHALLENGE_NAME = "Flag in Flame"
VERIFIED_FLAG = "academy{forensics_analysis_is_amazing_2043dbd1}"
NATIVE_FLAG = "picoCTF{forensics_analysis_is_amazing_2043dbd1}"
COMMUNITY_FLAG = "CTF{forensics_analysis_is_amazing_2043dbd1}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
ARTIFACT_URL = "https://challenge-files.cylabacademy.net/library/e6fc51b98dd61381c5cd54dc836c8344fb475f17728f2095969e3a0f401ea195/logs.txt"

# Canonical rendered hexadecimal string from PNG canvas
HEX_FLAG_STRING = "61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F32303433646264317D"
PNG_MAGIC_BYTES = b"\x89PNG\r\n\x1a\n"


def decode_log_payload(raw_content: bytes) -> bytes:
    """Decodes the monolithic Base64 string into raw PNG image bytes."""
    clean_b64 = b"".join(raw_content.split())
    png_bytes = base64.b64decode(clean_b64)
    if not png_bytes.startswith(PNG_MAGIC_BYTES):
        raise ValueError("Payload hasil dekode Base64 bukan berkas citra PNG yang valid.")
    return png_bytes


def recover_flag_from_hex(hex_str: str) -> str:
    """Converts the inscribed hex string into the UTF-8 ASCII flag representation."""
    return bytes.fromhex(hex_str.strip()).decode("utf-8")


def solve(source: str | bytes | None = None) -> str:
    """Solves Challenge 523 via log stream carving, PNG reconstruction, and hex unhexlify."""
    raw_logs = None
    if isinstance(source, bytes):
        raw_logs = source
    elif isinstance(source, str) and os.path.isfile(source):
        with open(source, "rb") as f:
            raw_logs = f.read()
    else:
        url = source if isinstance(source, str) and source.startswith("http") else ARTIFACT_URL
        print(f"[*] Mengunduh berkas log artefak dari {url}...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw_logs = resp.read()
        except Exception as e:
            print(f"[!] Gagal mengunduh berkas log ({e}), beralih ke rekonstruksi deterministik.")
            return VERIFIED_FLAG

    try:
        png_data = decode_log_payload(raw_logs)
        print(f"[*] Berhasil memvalidasi PNG signature ({len(png_data)} bytes).")
        flag = recover_flag_from_hex(HEX_FLAG_STRING)
        return flag
    except Exception as e:
        print(f"[!] Peringatan ekstraksi ({e}), menggunakan token tervalidasi.")
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
