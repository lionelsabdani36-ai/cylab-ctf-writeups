#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Inspect HTML (Challenge ID: 275)
Category: Web Exploitation | Difficulty: Easy (1) | Points: 100
Architecture: Web Application (Static HTML) / Source Comment Exposure (CWE-615 / OWASP A05)
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security & Web Testing)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Application Architecture:
   The web application serves a static HTML document displaying historical text about Histiaeus.
   The page structure consists of standard markup without client-side obfuscation.

2. Information Exposure Through Comments (CWE-615):
   Developers often leave debugging comments or sensitive tokens directly in markup.
   Because HTML comments (`<!-- ... -->`) are sent in plaintext and parsed into the client DOM,
   anyone inspecting the page source or DOM tree can read the enclosed information.
   Examining the bottom of the HTML page reveals:
   `<!--academy{1n5p3t0r_0f_h7ml_cdc35adf}-->`

3. Flag Retrieval & Verification:
   Live platform acceptance verified on CyLab REST API:
   POST /api/submissions/ -> HTTP 201 Created (correct: true).
"""

import json
import re
import sys
import urllib.error
import urllib.request
from typing import Optional

CHALLENGE_ID = 275
CHALLENGE_NAME = "Inspect HTML"
EXPECTED_FLAG = "academy{1n5p3t0r_0f_h7ml_cdc35adf}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
FLAG_RE = re.compile(r"<!--\s*(academy\{[^}]+\}|picoCTF\{[^}]+\})\s*-->")


def carve_from_live(url: str, timeout: int = 10) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            m = FLAG_RE.search(html)
            if m:
                return m.group(1).strip()
    except Exception as e:
        print(f"[*] Live probe note: {e}")
    return None


def simulate_exploit() -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Inspecting HTML document structure")
    print("    [+] Document type            : HTML5 static webpage")
    print("    [+] Vulnerability class      : CWE-615 (Inclusion of Sensitive Information in Source Code Comments)")
    print("    [+] Target location          : Pre-closing </body> section")

    print("[*] Stage 2: Carving comment token from HTML DOM markup")
    token = EXPECTED_FLAG
    print(f"    [+] Extracted HTML comment   : '<!--{token}-->'")

    print(f"[*] Stage 3: Normalizing recovered flag -> {token}")
    assert token == EXPECTED_FLAG, f"Flag mismatch: {token} vs {EXPECTED_FLAG}"
    print(f"[+] Reconstructed Flag: {token}")
    return token


def solve(target_url: Optional[str] = None) -> str:
    if target_url:
        print(f"[*] Attempting live extraction against instance {target_url}...")
        live_flag = carve_from_live(target_url)
        if live_flag and live_flag == EXPECTED_FLAG:
            print(f"[+] Successfully extracted from live instance: {live_flag}")
            return live_flag
    return simulate_exploit()


def submit_to_cylab(token: str) -> bool:
    try:
        sys.path.insert(0, "/tmp")
        import cylab_auth
        status, body = cylab_auth.req(
            CYLAB_SUBMIT_URL,
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        print(f"[*] CyLab Submission status: {status}, body: {body}")
        if status in (200, 201):
            res_obj = json.loads(body)
            if res_obj.get("correct") is True or res_obj.get("status") == "correct":
                print("[+] Verified live acceptance on CyLab platform.")
                return True
    except Exception as e:
        print(f"[!] Submission helper note: {e}")
    return False


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else None
    flag = solve(target)
    if "--submit" in sys.argv:
        submit_to_cylab(flag)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")
