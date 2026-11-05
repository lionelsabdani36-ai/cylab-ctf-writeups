#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 85: First Grep (picoCTF 2019)
Category: General Skills / Regular Expression & Pattern Searching
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Information Gathering & Log/Text Analysis Techniques)
CWE: CWE-312 (Cleartext Storage of Sensitive Information)

Description:
Can you find the flag in the file? This would be really tedious to look through manually,
something tells me there is a better way.

Methodology:
- The target asset contains 14,546 characters of random alphanumeric filler strings.
- Using POSIX regular expression searching (grep / re module) matching the canonical flag wrapper pattern:
  (?:academy|picoCTF)\\{[^}]+\\}
- Recovers the embedded flag token in O(N) linear time complexity.
- Recovered flag: academy{grep_is_good_to_find_things_3FCACd2A}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/5d7f4358263155557302dec0109cb10471df58afe72ce4507fc85ade2e3476c3/file"
EXPECTED_FLAG = "academy{grep_is_good_to_find_things_3FCACd2A}"


def solve(file_path: str | None = None) -> str:
    content = ""
    if file_path and os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    elif os.path.exists("file"):
        with open("file", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    elif os.path.exists("/tmp/cylab_file.txt"):
        with open("/tmp/cylab_file.txt", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    else:
        req = urllib.request.Request(ASSET_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")

    m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", content)
    if not m:
        raise ValueError("Flag pattern not found in file content")

    flag = m.group(0)
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
