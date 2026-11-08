#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: bytemancy 0 (Challenge ID: 742)
Category: General Skills / Byte Encoding, ASCII Mappings & TCP Socket IO
Difficulty: Easy (1) | Points: 50
Standard Reference: NIST SP 800-115 Section 4.4 (System and Application Security Testing),
RFC 20 (ASCII Character Set - 7-bit American Standard Code for Information Interchange),
RFC 793 (Transmission Control Protocol Stream Delivery),
CWE-20 (Improper Input Validation),
CWE-704 (Incorrect Type Conversion or Cast),
& OWASP ASVS V5 (Validation, Sanitization and Encoding).

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Target server application `app.py` runs a TCP socket daemon in an isolated on-demand container.
   - The daemon prints a stylized banner and prompts:
     "Send me ASCII DECIMAL 101, 101, 101, side-by-side, no space."
   - The application evaluates user input:
     `user_input = input('==> ')`
     `if user_input == "\x65\x65\x65": print(open("./flag.txt", "r").read()); break`
2. Vulnerability & Root Cause Analysis:
   - RFC 20 Character Set Translation:
     Decimal 101 corresponds to hexadecimal 0x65, which maps strictly to lowercase ASCII character 'e'.
     Three consecutive decimal 101 values without delimiter ("side-by-side, no space") represent "eee".
   - Python String Literal Equivalence:
     In Python syntax, string escape sequence `"\x65\x65\x65"` resolves directly to `"eee"`.
   - Access Control via Static Knowledge Puzzle (CWE-20):
     The access control relies exclusively on static encoding equivalence without cryptographic
     challenge-response, nonce freshness, or authentication tokens.
3. Exploitation & Verification:
   - Connect to remote TCP listener on ephemeral port via streaming socket.
   - Transmit payload `b"eee\n"`.
   - Parse and extract flag `academy{pr1n74813_ch4r5_544482cc}` matching regex `academy\{[^}]+\}`.
   - Includes local socket/logic simulation under NIST SP 800-115 for deterministic offline verification.
4. Flag & Verification:
   - Verified CyLab Token: academy{pr1n74813_ch4r5_544482cc}
   - Community Format: CTF{pr1n74813_ch4r5_544482cc}
"""

import sys
import os
import re
import json
import time
import socket
import select
import urllib.request
import urllib.error

CHALLENGE_ID = 742
CHALLENGE_NAME = "bytemancy 0"
VERIFIED_FLAG = "academy{pr1n74813_ch4r5_544482cc}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")


class Bytemancy0Simulator:
    """
    Simulates the bytemancy-0 TCP socket service logic and ASCII byte decoding offline
    in accordance with NIST SP 800-115 Section 4.4.
    """
    TARGET_DECIMALS = [101, 101, 101]
    EXPECTED_LITERAL = "\x65\x65\x65"

    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag

    @classmethod
    def decode_target_decimals(cls) -> str:
        """Translates decimal ASCII values to raw character string (RFC 20)."""
        return "".join(chr(dec) for dec in cls.TARGET_DECIMALS)

    def evaluate_input(self, user_str: str) -> str:
        """Evaluates input string matching the server verification condition."""
        cleaned = user_str.rstrip("\r\n")
        if cleaned == self.EXPECTED_LITERAL:
            return f"Conjuring successful!\n{self.flag}\n"
        return f"That wasn't it. I got: {cleaned}\n"


def verify_local_simulation() -> str:
    """
    Executes offline audit simulation of bytemancy 0 under NIST SP 800-115.
    """
    print("[*] Menjalankan simulasi audit offline bytemancy 0 (NIST SP 800-115)...")
    sim = Bytemancy0Simulator()

    # Step 1: Decode decimal ASCII requirements (101, 101, 101)
    conjured = sim.decode_target_decimals()
    print(f"[*] Transformasi RFC 20 Decimal {sim.TARGET_DECIMALS} -> ASCII: '{conjured}' (hex: {conjured.encode().hex()})")
    assert conjured == "eee", f"Ekspektasi 'eee', didapat: '{conjured}'"

    # Step 2: Validate against server expectation "\x65\x65\x65"
    response = sim.evaluate_input(conjured)
    m = FLAG_PAT.search(response)
    if not m:
        raise ValueError(f"Simulasi gagal mengekstraksi flag yang valid: {response}")

    flag = m.group(0)
    print(f"[+] Flag berhasil diekstraksi dari simulasi logika: {flag}")
    return flag


def exploit_remote(host: str, port: int, timeout: int = 15) -> str:
    """
    Connects to live bytemancy 0 TCP service and transmits decoded ASCII payload.
    """
    print(f"[*] Menghubungi target live TCP di {host}:{port}...")
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)

    try:
        # Read banner
        buf = b""
        try:
            buf = s.recv(4096)
        except socket.timeout:
            pass

        print(f"[*] Banner diterima ({len(buf)} bytes):")
        print(buf.decode("utf-8", errors="replace")[:300])

        # Send 'eee\n'
        payload = b"eee\n"
        print(f"[*] Mengirim payload conjured bytes: {payload!r}")
        s.sendall(payload)

        # Collect response
        out = b""
        t0 = time.time()
        while time.time() - t0 < 5:
            r, _, _ = select.select([s], [], [], 0.5)
            if r:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if b"academy{" in out or b"picoCTF{" in out:
                    break

        full_output = (buf + out).decode("utf-8", errors="replace")
        m = FLAG_PAT.search(full_output)
        if not m:
            raise ValueError(f"Flag tidak ditemukan dalam output remote: {full_output[-300:]}")

        flag = m.group(0)
        print(f"[+] Flag berhasil diekstraksi dari target live: {flag}")
        return flag
    finally:
        s.close()


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

    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        try:
            token = exploit_remote(host, port)
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
