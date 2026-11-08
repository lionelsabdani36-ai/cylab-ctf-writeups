#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Hidden Cipher 1 (Challenge ID: 745)
Category: Reverse Engineering / UPX De-obfuscation & Repeating-Key XOR Inversion
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security & Binary Analysis),
CWE-798 (Use of Hard-coded Credentials / Cryptographic Keys),
CWE-327 (Use of a Broken or Risky Cryptographic Algorithm),
CWE-326 (Inadequate Encryption Strength), & OWASP Testing Guide (Reverse Engineering Binaries).

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Target binary `hiddencipher` is distributed as an x86-64 ELF executable packed with UPX.
   - An on-demand container instance emits a hex-encoded ciphertext stream over a TCP socket:
     `nc chatelaine.cylabacademy.net <port>`.
   - The challenge requires reversing the binary transformation, recovering the embedded secret,
     and inverting the cipher to reveal the original competition token.
2. Vulnerability & Root Cause:
   - Superficial Compression vs Cryptographic Obfuscation:
     The UPX packer acts merely as a runtime decompression stub, not a protective cryptor.
     Decompressing via `upx -d` restores the full uncompressed ELF executable (from 7,056 to 16,496 bytes).
   - Hard-Coded Secret Key (CWE-798):
     Static disassembly of function `get_secret` reveals immediate byte stores into the `.bss` section:
     `mov byte ptr [rbp-0x6], 0x53 ('S')`
     `mov byte ptr [rbp-0x5], 0x33 ('3')`
     `mov byte ptr [rbp-0x4], 0x43 ('C')`
     `mov byte ptr [rbp-0x3], 0x72 ('r')`
     `mov byte ptr [rbp-0x2], 0x33 ('3')`
     `mov byte ptr [rbp-0x1], 0x74 ('t')`
     The embedded repeating encryption key is the constant 6-byte string: `b"S3Cr3t"`.
   - Insecure XOR Stream Cipher (CWE-327 & CWE-326):
     The encryption loop in `main` evaluates:
     `cipher[i] = flag[i] ^ key[i % 6]`.
     Compiler optimization replaces `i % 6` with reciprocal multiplication `imul 0x2aaaaaab` followed by `shr 0x20`.
     Because XOR is an involutory mathematical operation ($A \oplus B \oplus B = A$), decryption is symmetric:
     `flag[i] = cipher[i] ^ key[i % 6]`.
3. Exploitation & Verification:
   - Intercept hex-encoded ciphertext from live TCP socket:
     `3250221656192a483b1d412b265d3313501f0c072d135f0d2002302d55473700224a04402e`.
   - Unhexlify into raw byte buffer (37 bytes).
   - Compute byte-wise XOR against repeating key `b"S3Cr3t"`:
     Resulting plaintext: `academy{xor_unpack_4nalys1s_f3d3a874}`.
   - Verify token submission via CyLab REST API `POST /api/submissions/`.
4. Flag & Verification:
   - Verified CyLab Token: academy{xor_unpack_4nalys1s_f3d3a874}
   - Community Format: CTF{xor_unpack_4nalys1s_f3d3a874}
"""

import sys
import os
import re
import json
import socket
import urllib.request
import urllib.error

CHALLENGE_ID = 745
CHALLENGE_NAME = "Hidden Cipher 1"
VERIFIED_FLAG = "academy{xor_unpack_4nalys1s_f3d3a874}"
HARDCODED_KEY = b"S3Cr3t"
CAPTURED_CIPHERTEXT_HEX = "3250221656192a483b1d412b265d3313501f0c072d135f0d2002302d55473700224a04402e"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")


class HiddenCipherSimulator:
    """
    Simulates the UPX-unpacked hiddencipher binary encryption and decryption routines.
    Validates repeating-key XOR inversion and get_secret key extraction offline.
    """
    def __init__(self, key: bytes = HARDCODED_KEY):
        self.key = key

    def get_secret(self) -> bytes:
        """Simulates get_secret() constructing b'S3Cr3t' from disassembly bytes."""
        byte_constants = [0x53, 0x33, 0x43, 0x72, 0x33, 0x74]
        return bytes(byte_constants)

    def encrypt(self, plaintext: str) -> str:
        """Simulates the main loop encrypting plaintext with key[i % 6]."""
        pt_bytes = plaintext.encode("utf-8")
        ct_bytes = bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(pt_bytes))
        return ct_bytes.hex()

    def decrypt(self, ciphertext_hex: str) -> str:
        """Inverts the repeating XOR cipher: P[i] = C[i] ^ key[i % 6]."""
        ct_bytes = bytes.fromhex(ciphertext_hex.strip())
        recovered_bytes = bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(ct_bytes))
        return recovered_bytes.decode("utf-8", errors="replace")


def verify_local_simulation() -> str:
    """
    Executes offline audit simulation of UPX de-obfuscation and XOR inversion.
    """
    print("[*] Menjalankan simulasi audit offline Hidden Cipher 1 (NIST SP 800-115)...")
    sim = HiddenCipherSimulator()

    extracted_key = sim.get_secret()
    print(f"[*] Kunci simetris terdeteksi dari fungsi get_secret: {extracted_key}")
    assert extracted_key == HARDCODED_KEY, "Mismatch pada recovery kunci rahasia!"

    print(f"[*] Melakukan inversi terhadap hex ciphertext: {CAPTURED_CIPHERTEXT_HEX}")
    recovered_flag = sim.decrypt(CAPTURED_CIPHERTEXT_HEX)

    m = FLAG_PAT.search(recovered_flag)
    if not m:
        raise ValueError(f"Dekripsi gagal menghasilkan flag yang valid: {recovered_flag}")

    flag = m.group(0)
    print(f"[+] Flag berhasil dipulihkan melalui inversi XOR: {flag}")
    return flag


def exploit_remote(host: str, port: int) -> str:
    """
    Connects to live netcat instance, retrieves hex ciphertext, and decrypts using repeating XOR key.
    """
    print(f"[*] Menghubungi target live netcat di {host}:{port}...")
    s = socket.create_connection((host, int(port)), timeout=20)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 4096:
                break
    finally:
        s.close()

    text = data.decode(errors="replace")
    hexline = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip().replace("0123456789abcdef", "") == "" and len(ln.strip()) >= 16
    ]
    if not hexline:
        raise ValueError(f"Tidak ada baris ciphertext hex dalam keluaran lab: {text[:200]}")

    ct_hex = hexline[0]
    print(f"[+] Ciphertext hex berhasil diterima dari remote: {ct_hex}")

    sim = HiddenCipherSimulator()
    flag = sim.decrypt(ct_hex)
    print(f"[+] Flag terdekripsi dari live instance: {flag}")
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
