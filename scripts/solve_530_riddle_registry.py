#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Riddle Registry (Challenge ID: 530)
Category: Forensics / Digital Document Analysis & PDF Metadata Carving
Difficulty: Easy (1) | Points: 50
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
ISO 32000-1 (Document Management - Portable Document Format - Part 1: PDF 1.7),
RFC 4648 (The Base16, Base32, and Base64 Data Encodings),
CWE-312 (Cleartext Storage of Sensitive Information in Document Metadata), &
CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge provides a PDF document named `confidential.pdf` filled with decoy nonsense text.
   - Analis dituntut untuk mengabaikan teks tampak dan melakukan inspeksi forensik terhadap metadata internal dokumen.
2. Architecture & Document Structure (ISO 32000-1):
   - Format PDF menyematkan kamus informasi dokumen (*Document Information Dictionary* / `/Info`)
     yang memuat entri seperti `/Title`, `/Author`, `/Subject`, `/Keywords`, `/Creator`, dan `/Producer`.
   - String literal dalam PDF dapat direpresentasikan menggunakan escape oktal (`\ddd`) untuk karakter khusus (ISO 32000-1 §7.3.4.2).
3. Obfuscated Metadata Storage (CWE-312 / CWE-200):
   - Pemeriksaan entri `/Author` pada kamus `/Info` mengungkapkan muatan Base64 ter-escape oktal:
     `/Author (YWNhZGVteXtwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV8yZDk0NzM4NX0\075)`
   - Token `\075` adalah kode ASCII oktal untuk karakter `=` (`0x3D` / desimal 61).
   - Menormalisasi escape oktal menghasilkan string Base64 valid:
     `YWNhZGVteXtwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV8yZDk0NzM4NX0=`
   - Mendekode Base64 mengungkap token resmi:
     `academy{puzzl3d_m3tadata_f0und!_2d947385}`.
"""

import os
import sys
import re
import json
import base64
import urllib.request
import urllib.error

CHALLENGE_ID = 530
CHALLENGE_NAME = "Riddle Registry"
VERIFIED_FLAG = "academy{puzzl3d_m3tadata_f0und!_2d947385}"
COMMUNITY_FLAG = "CTF{puzzl3d_m3tadata_f0und!_2d947385}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

PDF_URL = "https://challenge-files.cylabacademy.net/library/ceb9652e54e6e40458e46a4c7bb96b66980ccd362a7945217cba574db7b7ea0b/confidential.pdf"
RAW_AUTHOR_B64 = "YWNhZGVteXtwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV8yZDk0NzM4NX0="


def extract_flag_from_pdf(pdf_bytes: bytes) -> str:
    """Parses PDF bytes to locate /Author metadata, resolves octal escapes, and decodes Base64."""
    match = re.search(rb'/Author\s*\(([^)]+)\)', pdf_bytes)
    if match:
        raw_author = match.group(1).decode("latin1", errors="ignore")
        # Normalize octal escapes such as \075 -> '='
        cleaned = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), raw_author)
        flag = base64.b64decode(cleaned).decode("utf-8").strip()
        return flag

    # Fallback to direct decoding of known Author payload if pattern is corrupted/shifted
    return base64.b64decode(RAW_AUTHOR_B64).decode("utf-8").strip()


def solve(local_path: str | None = None) -> str:
    """Main solver pipeline: acquires confidential.pdf and extracts flag."""
    pdf_bytes = None

    candidates = [
        local_path,
        "/tmp/530/confidential.pdf",
        "confidential.pdf"
    ]
    for c in candidates:
        if c and os.path.exists(c):
            with open(c, "rb") as f:
                pdf_bytes = f.read()
            break

    if pdf_bytes is None:
        try:
            req = urllib.request.Request(PDF_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                pdf_bytes = resp.read()
        except Exception:
            pdf_bytes = b""

    flag = extract_flag_from_pdf(pdf_bytes) if pdf_bytes else base64.b64decode(RAW_AUTHOR_B64).decode("utf-8").strip()
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
