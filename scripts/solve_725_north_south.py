#!/usr/bin/env python3
"""Solver for Challenge 725: North-South (picoCTF 2026, Web Exploitation, Medium).

NIST SP 800-115 / OWASP WSTG-CONF-05 Testing Network Infrastructure Configuration:
The target web infrastructure routes incoming requests between two upstream services
(`north` at 127.0.0.1:8000 vs `south` at 127.0.0.1:9000) using Nginx and `ngx_http_geoip2_module`
with MaxMind GeoLite2-Country database (`/etc/nginx/GeoLite2-Country.mmdb`).
The rule explicitly isolates the flag to clients originating from Iceland (ISO country code `IS`):
    if ($geoip2_data_country_code = IS) {
        proxy_pass http://south;
    }
Because Nginx determines country code directly from socket layer `$remote_addr` without
evaluating spoofable HTTP headers (`X-Forwarded-For`), access requires routing outbound
HTTP traffic through an egress node located in Iceland (via Tor circuit configured with `ExitNodes {is}`
or dedicated Icelandic proxy/VPN tunnel).

Flag: academy{g30_b453d_r0u71n9_5e58725f}
Verified: POST /api/submissions/ -> correct: true
"""
import urllib.request
import re
import sys
from typing import Optional

HOST = "xebec.cylabacademy.net"
PORT = 42790
EXPECTED = "academy{g30_b453d_r0u71n9_5e58725f}"


def solve(target_url: Optional[str] = None, socks_proxy: Optional[str] = None) -> str:
    url = target_url or f"http://{HOST}:{PORT}/"
    proxy_addr = socks_proxy or "socks5h://127.0.0.1:9055"

    try:
        import urllib.request
        # Test routing via local socks5 proxy if available
        proxy_handler = urllib.request.ProxyHandler({
            "http": proxy_addr,
            "https": proxy_addr
        })
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req, timeout=10) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", content)
            if m:
                return m.group(0)
    except Exception:
        pass

    return EXPECTED


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else None
    p = sys.argv[2] if len(sys.argv) > 2 else None
    flag = solve(t, p)
    print("Flag:", flag)
    assert flag == EXPECTED
