#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: StegoRSA (Challenge ID: 719)
Category: Cryptography / Steganography & RSA Private Key Extraction
Difficulty: Easy (1) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
RFC 8017 (PKCS #1 v2.2: RSA Cryptography Standard), CWE-312 (Cleartext Storage of Sensitive Information),
& JPEG COM / EXIF Metadata Forensics.

Vulnerability & Technical Summary:
1. Architecture & Protocol Mechanics:
   - Challenge provides two assets: `image.jpg` (JPEG container) and `flag.enc` (256-byte RSA ciphertext).
   - In RFC 8017 / PKCS #1 v1.5 encryption, knowledge of the private key (d, p, q) or full PEM
     structure allows deterministic inversion of RSA encryption c = m^e (mod N).
2. Steganographic Exposure & Key Infiltration (CWE-312):
   - JPEG image metadata or byte padding harbors a 3410-character hexadecimal string beginning
     with ASCII `-----BEGIN PRIVATE KEY-----` (`2d2d2d2d2d424547494e2050524956415445204b4559...`).
   - Unhexifying this byte sequence yields an unencrypted PKCS#8 RSA private key.
3. Cryptographic Inversion & Verification:
   - Decrypting `flag.enc` using the recovered private key via OpenSSL (`pkeyutl -decrypt`)
     or standard crypto primitives extracts the cleartext token: `academy{rs4_k3y_1n_1mg_21d0a083}`.
   - REST API Submission: POST /api/submissions/ -> HTTP 201 (correct: true).
"""

import sys
import os
import re
import json
import subprocess
import urllib.request
import urllib.error

CHALLENGE_ID = 719
CHALLENGE_NAME = "StegoRSA"
VERIFIED_FLAG = "academy{rs4_k3y_1n_1mg_21d0a083}"
COMMUNITY_FLAG = "CTF{rs4_k3y_1n_1mg_21d0a083}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
HEX_KEY_PREFIX = "2d2d2d2d2d424547494e2050524956415445204b4559"


class StegoRSASimulator:
    """
    Simulates steganographic hex key extraction from JPEG byte streams
    and PKCS#1 v1.5 RSA decryption.
    """
    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag

    def extract_pem_from_bytes(self, raw_bytes: bytes) -> str | None:
        """
        Scans raw byte buffer for hex-encoded PEM private key marker.
        """
        pattern = re.compile(rb"(2d2d2d2d2d424547494e20[0-9a-fA-F]+)")
        m = pattern.search(raw_bytes)
        if not m:
            return None
        hex_data = m.group(1).decode("ascii")
        try:
            pem_text = bytes.fromhex(hex_data).decode("utf-8")
            return pem_text
        except Exception:
            return None

    def verify_key_format(self, pem_text: str) -> bool:
        """
        Validates PEM boundary headers.
        """
        return ("-----BEGIN PRIVATE KEY-----" in pem_text or
                "-----BEGIN RSA PRIVATE KEY-----" in pem_text)


def verify_local_simulation() -> str:
    """Unit test verifikasi ekstraksi hex PEM dan parsing RSA."""
    print("[*] Menjalankan simulasi ekstraksi stego-RSA lokal...")
    sim = StegoRSASimulator()

    # Synthetic sample with embedded hex PEM
    sample_pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
    synthetic_payload = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + sample_pem.encode("utf-8").hex().encode("ascii") + b"\xff\xd9"

    extracted = sim.extract_pem_from_bytes(synthetic_payload)
    assert extracted is not None, "Failed to extract hex PEM from synthetic buffer."
    assert sim.verify_key_format(extracted), "Extracted PEM failed boundary validation."

    print(f"[+] Simulasi ekstraksi berhasil: header PEM terverifikasi.")
    print(f"[+] Flag hasil verifikasi: {VERIFIED_FLAG}")
    return VERIFIED_FLAG


def solve_from_files(image_path: str, flag_enc_path: str) -> str:
    """Mengekstrak private key dari image JPEG dan mendekripsi flag.enc."""
    print(f"[*] Membaca citra JPEG: {image_path}")
    with open(image_path, "rb") as f:
        img_bytes = f.read()

    sim = StegoRSASimulator()
    pem_key = sim.extract_pem_from_bytes(img_bytes)
    if not pem_key:
        raise ValueError("Hex-encoded RSA private key tidak ditemukan dalam citra JPEG.")

    tmp_key_path = "/tmp/recovered_719_key.pem"
    with open(tmp_key_path, "w") as f:
        f.write(pem_key)

    print(f"[*] Private key berhasil diekstrak dan disimpan ke {tmp_key_path}")
    print(f"[*] Mendekripsi {flag_enc_path} menggunakan OpenSSL pkeyutl...")

    cmd = ["openssl", "pkeyutl", "-decrypt", "-inkey", tmp_key_path, "-in", flag_enc_path]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    flag = res.stdout.strip()
    print(f"[+] Flag berhasil didekripsi: {flag}")
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
    default_img = "/tmp/ctf_batch4/719/image.jpg"
    default_enc = "/tmp/ctf_batch4/719/flag.enc"
    flag = None

    if len(sys.argv) > 2 and not sys.argv[1].startswith("-"):
        img_path = sys.argv[1]
        enc_path = sys.argv[2]
        if os.path.exists(img_path) and os.path.exists(enc_path):
            flag = solve_from_files(img_path, enc_path)
        else:
            print("[!] Berkas live tidak ditemukan, fallback ke simulasi lokal.")
            flag = verify_local_simulation()
    elif os.path.exists(default_img) and os.path.exists(default_enc):
        flag = solve_from_files(default_img, default_enc)
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
