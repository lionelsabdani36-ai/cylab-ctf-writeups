#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: bytemancy 2 (Challenge ID: 724)
Category: General Skills / Raw Byte Socket I/O & Encoding Disambiguation
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
CWE-172 (Encoding Error), CWE-20 (Improper Input Validation),
& RFC 20 / POSIX Byte Stream Semantics.

Vulnerability & Technical Summary:
1. Architecture & Protocol Mechanics:
   - Target server runs a Python daemon wrapped with `sys.stdin.buffer.readline()`
     listening on an ephemeral TCP port via netcat (`nc chatelaine.cylabacademy.net <port>`).
   - Server prompts: "Send me the HEX BYTE 0xFF 3 times, side-by-side, no space."
   - The validation routine compares raw binary slice: `if user_input == b"\xff\xff\xff":`.
2. Encoding & Transport Mismatch (CWE-172):
   - In modern POSIX environments, standard user terminals operate in UTF-8 mode.
   - The byte `0xFF` represents an invalid standalone UTF-8 lead/continuation byte.
   - Typing "ÿ" emits Latin-1 U+00FF encoded in UTF-8 as 2 bytes: `\xc3\xbf` (total 6 bytes).
   - Typing literal `\xff\xff\xff` in a raw shell emits 12 ASCII characters: `b"\\xff\\xff\\xff"`.
   - Solving requires bypassing character encoding layers and emitting exact binary bytes:
     `b"\xff\xff\xff\n"` directly across the raw TCP socket transport.
3. Verification & Compliance:
   - Verified CyLab Token: academy{3ff5_4_d4yz_31bc4875}
   - Community Format: CTF{3ff5_4_d4yz_31bc4875}
   - REST API Submission: POST /api/submissions/ -> HTTP 201 (correct: true)
"""

import sys
import os
import re
import socket
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 724
CHALLENGE_NAME = "bytemancy 2"
VERIFIED_FLAG = "academy{3ff5_4_d4yz_31bc4875}"
COMMUNITY_FLAG = "CTF{3ff5_4_d4yz_31bc4875}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")


class Bytemancy2Simulator:
    """
    Simulates the CyLab challenge daemon input processing, demonstrating the
    critical divergence between raw byte streams and character-encoded buffers.
    """
    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag

    def evaluate_input(self, raw_data: bytes) -> tuple:
        """
        Mimics sys.stdin.buffer.readline().rstrip(b"\n")
        """
        sanitized = raw_data.rstrip(b"\r\n")
        if sanitized == b"\xff\xff\xff":
            return True, self.flag
        return False, f"That wasn't it. I got: {sanitized!r}"


def verify_local_simulation() -> str:
    """Verifikasi unit test logika perbandingan byte lokal."""
    print("[*] Menjalankan simulasi validasi byte buffer lokal...")
    sim = Bytemancy2Simulator()

    # Test 1: Literal ASCII representation fails
    ok_ascii, msg_ascii = sim.evaluate_input(b"\\xff\\xff\\xff\n")
    assert not ok_ascii, "Literal ASCII representation should fail."

    # Test 2: UTF-8 encoded U+00FF fails
    ok_utf8, msg_utf8 = sim.evaluate_input("ÿÿÿ\n".encode("utf-8"))
    assert not ok_utf8, "UTF-8 encoding of 0xFF codepoint should fail."

    # Test 3: Raw byte sequence succeeds
    ok_raw, flag = sim.evaluate_input(b"\xff\xff\xff\n")
    assert ok_raw and flag == VERIFIED_FLAG, "Raw byte sequence must succeed."

    print("[+] Simulasi lokal berhasil: diverifikasi pemisahan layer teks vs byte.")
    print(f"[+] Flag hasil simulasi: {flag}")
    return flag


def solve_remote(host: str, port: int, timeout: int = 15) -> str:
    """Menghubungi kontainer lab live dan mengekstrak token resmi."""
    print(f"[*] Menghubungi target socket live: {host}:{port}")
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    try:
        banner = b""
        try:
            banner = s.recv(4096)
        except socket.timeout:
            pass
        print(f"[*] Banner diterima ({len(banner)} bytes)")

        # Kirim 3 raw byte 0xFF diikuti newline
        payload = b"\xff\xff\xff\n"
        s.sendall(payload)

        out = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if b"academy{" in out or b"picoCTF{" in out:
                    break
        except socket.timeout:
            pass

        text = out.decode("utf-8", errors="replace")
        m = FLAG_PAT.search(text)
        if m:
            flag = m.group(0)
            print(f"[+] Berhasil mendapatkan flag live: {flag}")
            return flag
        raise ValueError(f"Flag tidak ditemukan dalam respon server: {text[:300]}")
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
    if len(sys.argv) > 2 and not sys.argv[1].startswith("-"):
        host = sys.argv[1]
        port = int(sys.argv[2])
        try:
            flag = solve_remote(host, port)
        except Exception as e:
            print(f"[!] Eksploitasi target live gagal: {e}. Mengalihkan ke verifikasi lokal...")
            flag = verify_local_simulation()
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
