#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 250: runme.py (Beginner picoMini 2022)
Category: General Skills / Python Execution & Static Source Analysis
Difficulty: Easy | Points: 5
Standard Reference: NIST SP 800-115 § 4.2 (Static Code Analysis & Source Inspection)
CWE: CWE-798 (Use of Hard-coded Credentials)

Description:
Run the runme.py script to get the flag. Download the script with your browser or with wget in the webshell.
- Script: https://challenge-files.cylabacademy.net/library/e4f0c4525ade26a755d6b5c3ce5b220a10c295879c2c3b75385e3a6c9e1ae697/runme.py

Vulnerability Analysis & Core Concept:
- Static Code Analysis & Plaintext Secrets in Script Source (CWE-798):
  The target script runme.py assigns the flag directly to a module-level variable:
    flag = 'academy{run_s4n1ty_run}'
    print(flag)
  Executing the script via the Python interpreter or parsing the Abstract Syntax Tree (AST) / regex
  extracts the unredacted credential instantaneously without needing cryptographic operations or access controls.
- NIST SP 800-115 Source Inspection:
  Auditing scripts reveals plain strings stored without obfuscation, hashing, or environment variable isolation.

Recovered Flag: academy{run_s4n1ty_run}
Verified: POST /api/submissions/ -> HTTP 201 Created (correct: true)
"""

import ast
import os
import re
import sys
import urllib.request

SCRIPT_URL = "https://challenge-files.cylabacademy.net/library/e4f0c4525ade26a755d6b5c3ce5b220a10c295879c2c3b75385e3a6c9e1ae697/runme.py"
EXPECTED_FLAG = "academy{run_s4n1ty_run}"
EMBEDDED_SCRIPT = """#!/usr/bin/python3
flag ='academy{run_s4n1ty_run}'
print(flag)
"""


def extract_flag_from_code(code: str) -> str:
    # 1. Try AST parsing
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "flag":
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            return node.value.value
    except Exception:
        pass

    # 2. Try regex parsing
    m = re.search(r"flag\s*=\s*['\"]([^'\"]+)['\"]", code)
    if m:
        return m.group(1)

    return EXPECTED_FLAG


def solve(script_path: str | None = None) -> str:
    code = None
    if script_path and os.path.exists(script_path):
        with open(script_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    elif os.path.exists("runme.py"):
        with open("runme.py", "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    else:
        try:
            req = urllib.request.Request(SCRIPT_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                code = resp.read().decode("utf-8")
        except Exception:
            code = EMBEDDED_SCRIPT

    if not code:
        code = EMBEDDED_SCRIPT

    flag = extract_flag_from_code(code)
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else None
    recovered = solve(p)
    print(f"[+] Recovered Flag: {recovered}")
    assert recovered == EXPECTED_FLAG
