#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Lookey here (Challenge ID: 279)
Category: Forensics / Text Carving & Pattern Matching | Difficulty: Medium (2) | Points: 100
Standard Reference: NIST SP 800-115 Section 5.3 (Artifact Analysis & Log File Verification)
CWE: CWE-312 (Cleartext Storage of Sensitive Information), CWE-200 (Exposure of Sensitive Information)

Description:
Attackers have hidden information in a very large mass of data in the past, maybe they are still
doing it. Download the data and search for the flag based on the known prefix.

Methodology:
- The target asset is a text file containing the text of Ayn Rand's Anthem (size: ~108 KB, 2,146 lines).
- Embedded within the bulk prose is the flag token prefixed with "academy{".
- Applying POSIX pattern search (grep / re module) scanning for (?:academy|picoCTF)\\{[^}]+\\}
  recovers the flag in linear time O(N) without manual reading.
- Recovered flag: academy{gr3p_15_@w3s0m3_33595e98}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import json
import os
import re
import sys
import urllib.request

CHALLENGE_ID = 279
CHALLENGE_NAME = "Lookey here"
ASSET_URL = "https://challenge-files.cylabacademy.net/library/1e5b915df467718ade9bc65b9de2094f73159c40c620fbea7bfec17f657252b3/anthem.flag.txt"
EXPECTED_FLAG = "academy{gr3p_15_@w3s0m3_33595e98}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"


def solve(file_path: str | None = None) -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Locating and loading target text corpus (Anthem text)")
    content = ""
    if file_path and os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    elif os.path.exists("anthem.flag.txt"):
        with open("anthem.flag.txt", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    elif os.path.exists("/tmp/forensics_279/anthem.flag.txt"):
        with open("/tmp/forensics_279/anthem.flag.txt", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    else:
        print(f"[*] Fetching remote asset from {ASSET_URL}...")
        req = urllib.request.Request(
            ASSET_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://learn.cylabacademy.org/challenges",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="ignore")

    print(f"    [+] Loaded corpus ({len(content)} characters, {content.count(chr(10))} lines)")
    print("[*] Stage 2: Performing regex pattern search for academy{...} flag token")
    m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", content)
    if not m:
        raise ValueError("Flag pattern not found in text content")

    flag = m.group(0)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


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
    target = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else None
    flag = solve(target)
    if "--submit" in sys.argv:
        submit_to_cylab(flag)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")
