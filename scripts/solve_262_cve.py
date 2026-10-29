#!/usr/bin/env python3
"""Solver for Challenge 262 CVE-XXXX-XXXX (picoCTF 2022, Binary Exploitation).

The challenge asks for the first remote-code-execution CVE of 2021 in
the Windows Print Spooler service (used for printers/print servers),
excluding the Local Spooler bugs: PrintNightmare, CVE-2021-34527
(CWE-269 improper privilege management, CVSS 8.8, patched July 2021
out-of-band). The flag is the CVE ID in academy{} format; no lab
interaction needed.

Usage: python3 scripts/solve_262_cve.py
Verified: academy{CVE-2021-34527}
(POST /api/submissions/ -> correct:true)
"""
EXPECTED = "academy{CVE-2021-34527}"


def solve() -> str:
    print("PrintNightmare: Windows Print Spooler RCE, June-July 2021")
    print("Excludes Local Spooler (CVE-2021-1675 LPE). Answer: CVE-2021-34527")
    return EXPECTED


if __name__ == "__main__":
    print(solve())
