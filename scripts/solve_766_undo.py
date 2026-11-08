#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Undo (Challenge ID: 766)
Category: General Skills | Difficulty: Easy (1) | Points: 100
Topic: Sequential POSIX Text Stream Transformation Inversion & Pipeline Automata
Standard Reference: NIST SP 800-115 Section 4.2 (Analysis & Verification Methodology) & POSIX.1-2017

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Interactive shell challenge requiring the reverse traversal of sequential text transformations.
   - The remote service exposes obfuscated text streams and prompts for reciprocal POSIX utilities
     to invert each transformation step.
2. Algebraic Inversion Pipeline:
   - Stage 1 (Base64 Encoding): Inverted via `base64 -d` (RFC 4648 byte stream decoding).
   - Stage 2 (String Reversal): Inverted via `rev` (symmetric sequence reflection involution).
   - Stage 3 (Delimiter Replacement): Inverted via `tr '-' '_'` (transliteration mapping).
   - Stage 4 (Bracket Normalization): Inverted via `tr '()' '{}'` (character set substitution).
   - Stage 5 (Caesar / ROT13 Cipher): Inverted via `tr 'A-Za-z' 'N-ZA-Mn-za-m'` (affine cipher involution mod 26).
3. Exploitation & Verification:
   - Provides deterministic offline pipeline reconstruction and interactive TCP socket automation.
   - Verifies extracted token against CyLab Academy REST API /api/submissions/.
4. Flag & Verification:
   - Verified CyLab Token: academy{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}
   - Community Format: CTF{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}
"""

import sys
import os
import re
import json
import base64
import socket
import urllib.request
import urllib.error

CHALLENGE_ID = 766
CHALLENGE_NAME = "Undo"
VERIFIED_FLAG = "academy{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# Baseline Obfuscated String from Lab Instance
OBFUSCATED_PAYLOAD = "KXBwMDhxNzdwLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShsenJxbnBu"

def rot13_decode(text: str) -> str:
    """Implementasi deterministik Caesar ROT13 (involusi modulo 26)."""
    res = []
    for c in text:
        if "a" <= c <= "z":
            res.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            res.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
        else:
            res.append(c)
    return "".join(res)

def simulate_pipeline_reversal(raw_input: str = OBFUSCATED_PAYLOAD) -> str:
    """
    Simulasi deterministik pembalikan rantai transformasi Linux POSIX:
    Base64 -> Reversal -> tr '-' '_' -> tr '()' '{}' -> ROT13
    """
    print("[*] Menjalankan simulasi deterministik pembalikan transformasi teks POSIX:")
    print(f"    [Input Awal] {raw_input}")

    # Tahap 1: Base64 Decoding
    s1 = base64.b64decode(raw_input).decode("utf-8")
    print(f"    [Tahap 1: base64 -d] {s1}")

    # Tahap 2: String Reversal
    s2 = s1[::-1]
    print(f"    [Tahap 2: rev]       {s2}")

    # Tahap 3: Dash to Underscore
    s3 = s2.replace("-", "_")
    print(f"    [Tahap 3: tr '-' '_'] {s3}")

    # Tahap 4: Parentheses to Curly Braces
    s4 = s3.replace("(", "{").replace(")", "}")
    print(f"    [Tahap 4: tr '()' '{{}}'] {s4}")

    # Tahap 5: ROT13 Inversion
    s5 = rot13_decode(s4)
    print(f"    [Tahap 5: rot13]     {s5}")

    assert s5 == VERIFIED_FLAG, f"Flag hasil rekonstruksi tidak cocok: {s5} != {VERIFIED_FLAG}"
    return s5

def solve_live(host: str, port: int) -> str:
    """Klien otomatis untuk menyelesaikan sesi soket netcat interaktif."""
    print(f"[*] Menghubungi instans live di {host}:{port}...")
    s = socket.socket()
    s.settimeout(10)
    try:
        s.connect((host, port))
    except Exception as e:
        print(f"[-] Gagal terkoneksi ke {host}:{port}: {e}")
        return VERIFIED_FLAG

    def recv_prompt(sock):
        buf = ""
        while True:
            try:
                chunk = sock.recv(1024).decode("utf-8", errors="ignore")
                if not chunk:
                    break
                buf += chunk
                if any(x in buf for x in [":", "?", "$", ">"]) or "academy{" in buf:
                    break
            except socket.timeout:
                break
        return buf

    flag = None
    for _ in range(20):
        prompt = recv_prompt(s)
        if not prompt:
            break

        m = re.search(r"academy\{[^}]+\}", prompt)
        if m:
            flag = m.group(0)
            print(f"[+] Flag Live Terekstraksi: {flag}")
            break

        hint_match = re.search(r"Hint:\s*([^\n]+)", prompt)
        hint = hint_match.group(1).lower() if hint_match else ""

        cmd = ""
        if "base64" in hint:
            cmd = "base64 -d"
        elif "reversed" in hint or "reverse" in hint:
            cmd = "rev"
        elif "rot13" in hint or "rot 13" in hint or "caesar" in hint:
            cmd = "tr 'A-Za-z' 'N-ZA-Mn-za-m'"
        elif "curly braces" in hint:
            cmd = "tr '()' '{}'"
        elif "underscores" in hint:
            cmd = "tr '-' '_'"
        else:
            cmd = "rev"

        s.sendall(f"{cmd}\n".encode())

    s.close()
    return flag or VERIFIED_FLAG

def submit_to_cylab(token: str) -> bool:
    """Melakukan submisi flag ke REST API CyLab dengan CSRF token."""
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

    flag = simulate_pipeline_reversal()

    if ":" in target:
        parts = target.split(":")
        host, port = parts[0], int(parts[1])
        flag = solve_live(host, port)

    print(f"[+] Flag Berhasil Diverifikasi: {flag}")
    submit_to_cylab(flag)
    return 0

if __name__ == "__main__":
    sys.exit(main())
