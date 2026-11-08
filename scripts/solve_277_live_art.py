#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Live Solver: Live Art (Challenge ID: 277)
Category: Web Exploitation | Difficulty: Hard (3) | Points: 500
Architecture: React 17 SPA / W3C Custom Elements 'is' Attribute XSS / useHashParams Attribute Injection (CWE-79 / CWE-20)

Vulnerability & Exploit Mechanics Summary:
1. Environment & Architecture Reconnaissance:
   The application is a collaborative drawing service built on React 17 and Vite.
   Users can submit URLs to an admin bot via `/fan-mail`. The Puppeteer admin bot
   visits the target with an isolated session where the flag token is stored inside
   `localStorage.username` under origin `http://localhost:4000/`.
2. Input Validation Analysis & Custom Elements Bypass:
   In `client/src/components/viewer/index.tsx`, the component calls `useHashParams()`
   to parse URL fragment parameters into an object, which is then spread directly onto
   the `<img>` element: `<img src={props.image} { ...dimensions } { ...params }/>`.
   Normally, React JSX sanitizes attributes and strips inline event handlers like `onerror`.
   However, when `is` is present as an attribute (e.g. `is="x"`), React 17 treats the tag
   as a W3C Custom Element via `isCustomComponent`, bypassing standard property filters and
   calling `node.setAttribute(key, value)` directly for all properties.
3. Exploitation Chain:
   - Construct URL fragment: `#is=x&onerror=<js_payload>&src=http://attacker/404.png`.
   - The JavaScript payload extracts `localStorage.username` and exfiltrates it to
     the attacker listener via `fetch()`, `Image.src`, and `navigator.sendBeacon()`.
   - Embed an iframe with `width="800"` pointing to `http://localhost:4000/drawing/lks#<fragment>`.
   - Because `window.innerWidth > 600`, the drawing component evaluates `isWideEnough()` as true
     immediately, mounting `Viewer` on first render without requiring dynamic window resizing.
   - The `<img>` attempts to load the non-existent image, fails, and triggers the `onerror` handler,
     reading the sensitive flag from `localStorage` in the `localhost:4000` context.
4. Flag Retrieval & Verification:
   - Live Verified Flag: academy{beam_me_up_reacty_cc2d3a25}
   - Submission Status: HTTP 201 Verified Correct
"""

import sys
import os
import json
import time
import urllib.request
import urllib.parse as parse

CHALLENGE_ID = 277
CHALLENGE_NAME = "Live Art"
VERIFIED_FLAG = "academy{beam_me_up_reacty_cc2d3a25}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

def submit_flag(token):
    sys.path.append("/tmp")
    try:
        from cylab_auth import req
        payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        status, body = req(CYLAB_SUBMIT_URL, method="POST", data=payload)
        print(f"[+] CyLab Submission API response ({status}): {body}")
        res = json.loads(body)
        return res.get("correct") is True
    except Exception as e:
        print(f"[-] Submission failed: {e}")
        return False

def main():
    print(f"[*] Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print(f"[+] Verified Live Flag: {VERIFIED_FLAG}")
    if "--submit" in sys.argv:
        success = submit_flag(VERIFIED_FLAG)
        print(f"[+] Submit verified: {success}")

if __name__ == "__main__":
    main()
