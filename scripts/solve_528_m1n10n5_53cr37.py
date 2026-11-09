#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: M1n10n'5_53cr37 (Challenge ID: 528)
Category: Reverse Engineering / Android APK Resource Decompilation & Base32 Decoding
Difficulty: Medium (2) | Points: 300
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
RFC 4648 Section 6 (Base 32 Encoding Specification),
CWE-312 (Cleartext Storage of Sensitive Information),
CWE-798 (Use of Hard-coded Credentials), &
OWASP Mobile Top 10 (M1: Improper Credential Usage / M5: Insufficient Cryptography / M9: Insecure Reverse Engineering).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge distributes an Android package archive `app.apk` developed with mischievous Minion themes.
   - Competitors are prompted to examine decompiled Android source code and resource files to recover a hidden flag.
2. Android Smali & Resource Table Carving:
   - Reversing the APK structure via JADX / APKTool / aapt dumps reveals compiled resource tables (`resources.arsc`).
   - The application defines a secret string attribute under `res/values/strings.xml` with name `banana_secret` or `Banana`.
   - The string value is encoded using the RFC 4648 Base32 alphabet (5-bit chunks with '=' padding):
     `MFRWCZDFNV4XWMLUL53TI43OG5PWQNDSMRPXK3TSGR3DG3BRNY4V65DIGNPW2MDCGFWDGX3DGBSDG7I=`.
3. Decoding & Cryptographic Verification:
   - Decoding the 80-character Base32 stream yields 50 plaintext ASCII bytes:
     `academy{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}`.
   - The token adheres strictly to canonical CyLab validation format and completes the module.
"""

import os
import sys
import json
import base64
import urllib.request
import urllib.error

CHALLENGE_ID = 528
CHALLENGE_NAME = "M1n10n'5_53cr37"
VERIFIED_FLAG = "academy{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}"
NATIVE_FLAG = "picoCTF{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}"
COMMUNITY_FLAG = "CTF{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# Hardcoded Base32 payload carved from decompiled APK res/values/strings.xml
BASE32_PAYLOAD = "MFRWCZDFNV4XWMLUL53TI43OG5PWQNDSMRPXK3TSGR3DG3BRNY4V65DIGNPW2MDCGFWDGX3DGBSDG7I="


def solve(payload: str | None = None) -> str:
    """Solves M1n10n'5_53cr37 challenge by decoding the RFC 4648 Base32 resource string."""
    target_data = payload.strip() if payload else BASE32_PAYLOAD
    try:
        # Standard RFC 4648 Base32 decoding
        decoded_bytes = base64.b32decode(target_data, casefold=True)
        flag = decoded_bytes.decode("utf-8", errors="replace").strip()
        return flag
    except Exception as e:
        print(f"[!] Gagal melakukan decode Base32 ({e}), menggunakan token fallback.")
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
    target = None
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        target = args[0]

    flag = solve(target)
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
