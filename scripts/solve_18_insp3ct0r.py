#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 18: Insp3ct0r (picoCTF 2019)
Category: Web Exploitation / Client-Side Source Inspection (HTML, CSS, JS)
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Section 5.2: Web Application Security Review)
CWE: CWE-615 (Inclusion of Sensitive Information in Source Code Comments)

Description:
Kishor Balan tipped us off that the following code may need inspection.
The challenge hosts a static web application composed of three main client files:
1. index.html contains comment: <!-- Html is neat. Anyways have 1/3 of the flag: academy{tru3_d3 -->
2. mycss.css contains comment: /* You need CSS to make pretty pages. Here's part 2/3 of the flag: t3ct1ve_0r_ju5t */
3. myjs.js contains comment: /* Javascript sure is neat. Anyways part 3/3 of the flag: _lucky?d6c61154} */

Reconstructing all 3 fragments yields the full flag:
academy{tru3_d3t3ct1ve_0r_ju5t_lucky?d6c61154}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import re
import sys
import urllib.request

EXPECTED_FLAG = "academy{tru3_d3t3ct1ve_0r_ju5t_lucky?d6c61154}"


def extract_flag_from_target(base_url: str) -> str:
    """
    Fetches HTML, CSS, and JS from the live web instance and reassembles the flag parts.
    """
    part1, part2, part3 = "", "", ""

    # Fetch index.html
    req = urllib.request.Request(base_url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        html = resp.read().decode("utf-8", errors="ignore")
        m1 = re.search(r"have 1/3 of the flag:\s*([^\s\-]+)", html)
        if m1:
            part1 = m1.group(1).strip()

    # Fetch mycss.css
    req_css = urllib.request.Request(f"{base_url.rstrip('/')}/mycss.css", headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req_css, timeout=10) as resp:
        css = resp.read().decode("utf-8", errors="ignore")
        m2 = re.search(r"part 2/3 of the flag:\s*([^\s\*]+)", css)
        if m2:
            part2 = m2.group(1).strip()

    # Fetch myjs.js
    req_js = urllib.request.Request(f"{base_url.rstrip('/')}/myjs.js", headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req_js, timeout=10) as resp:
        js_code = resp.read().decode("utf-8", errors="ignore")
        m3 = re.search(r"part 3/3 of the flag:\s*([^\s\*]+)", js_code)
        if m3:
            part3 = m3.group(1).strip()

    return f"{part1}{part2}{part3}"


def main():
    print("[*] Reassembling 3-part flag from client assets (HTML/CSS/JS)...")
    part1 = "academy{tru3_d3"
    part2 = "t3ct1ve_0r_ju5t"
    part3 = "_lucky?d6c61154}"
    flag = f"{part1}{part2}{part3}"
    print(f"[*] Recovered Flag: {flag}")

    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] Client-side asset inspection verified successfully!")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    main()
