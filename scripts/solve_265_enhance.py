#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 265: Enhance! (picoCTF 2022)
Category: Forensics / Vector Graphics & XML Structure Analysis
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.2: Target Analysis & Document Carving)
CWE: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

Description:
Download this image file and find the flag.
- drawing.flag.svg

Methodology:
- Scalable Vector Graphics (SVG) is an XML-based vector image format (W3C RFC/Recommendation).
- Inspection of the DOM tree reveals hidden text embedded inside nested <tspan> elements
  under <text id="text3720">.
- The flag characters are distributed across sequential <tspan> nodes with localized coordinate
  shifts and whitespace padding to evade superficial visual rendering.
- By parsing the XML / regex extracting all <tspan> inner text and stripping whitespace,
  the full flag is recovered:
  academy{3nh4nc3d_001f8059}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET

ASSET_URL = "https://challenge-files.cylabacademy.net/library/248587d9a868db74a285623697f78ef3d87561aaa16ff1fb211fe88cd72f4a6c/drawing.flag.svg"
EXPECTED_FLAG = "academy{3nh4nc3d_001f8059}"


def solve(file_path: str | None = None) -> str:
    content = ""
    if file_path and os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    elif os.path.exists("drawing.flag.svg"):
        with open("drawing.flag.svg", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    else:
        req = urllib.request.Request(
            ASSET_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://learn.cylabacademy.org/challenges",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="ignore")

    # Method 1: Extract via regular expression matching <tspan> tags
    tspans = re.findall(r"<tspan[^>]*>(.*?)</tspan>", content, re.DOTALL)
    raw_flag = "".join(t.strip() for t in tspans if t.strip()).replace(" ", "").replace("\n", "")

    # Method 2: Fallback direct regex search for flag tokens in XML
    if "academy{" not in raw_flag and "picoCTF{" not in raw_flag:
        m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", content)
        if m:
            raw_flag = m.group(0)

    if not raw_flag or not ("{" in raw_flag and "}" in raw_flag):
        raise ValueError("Failed to recover flag from SVG structure")

    assert raw_flag == EXPECTED_FLAG, f"Flag mismatch: {raw_flag} != {EXPECTED_FLAG}"
    return raw_flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
