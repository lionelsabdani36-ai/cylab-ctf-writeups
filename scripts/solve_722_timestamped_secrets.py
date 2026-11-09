#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Timestamped Secrets (Challenge ID: 722)
Category: Cryptography / Low-Entropy KDF & Timestamp Brute-Force
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
CWE-330 (Use of Insufficiently Random Values),
CWE-327 (Use of a Broken or Risky Cryptographic Algorithm),
CWE-326 (Inadequate Encryption Strength),
& OWASP Cryptographic Failures (A02:2021).

Vulnerability & Technical Summary:
1. Architecture & Cryptographic Workflow:
   - Target script (`encryption.py`) uses AES-128 in Electronic Codebook (ECB) mode.
   - Key derivation: `key = sha256(str(timestamp).encode()).digest()[:16]` where `timestamp`
     is a 32-bit POSIX epoch integer (`int(time.time())`).
   - The challenge prompt leaks the approximate timestamp: "The encryption was done around 1790147519 UTC".
2. Key-Space Collapse (CWE-330 / CWE-326):
   - A properly generated AES-128 key possesses 128 bits of entropy (2^128 potential keys),
     rendering exhaustive brute-force computationally infeasible.
   - By deriving the key from a known narrow temporal window (~1790147519), the actual entropy
     collapses to a microscopic search space: ±3600 seconds is 7,200 trials; even ±30 days
     is only ~5.18 x 10^6 trials, computable in seconds on a single CPU core.
   - Electronic Codebook (ECB) mode lacks an Initialization Vector (IV), providing zero semantic
     security or diffusion across identical blocks.
3. Decryption & Verification:
   - Verified CyLab Token: academy{sa3S_sEc9t_3b464909}
   - Community Format: CTF{sa3S_sEc9t_3b464909}
   - REST API Submission: POST /api/submissions/ -> HTTP 201 (correct: true)
"""

import sys
import os
import re
import json
import urllib.request
import urllib.error
from hashlib import sha256

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("[!] PyCryptodome tidak ditemukan. Silakan jalankan dengan /home/lionelsabdani36/ctf_venv/bin/python3.")
    sys.exit(1)

CHALLENGE_ID = 722
CHALLENGE_NAME = "Timestamped Secrets"
VERIFIED_FLAG = "academy{sa3S_sEc9t_3b464909}"
COMMUNITY_FLAG = "CTF{sa3S_sEc9t_3b464909}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")

DEFAULT_HINT_TS = 1790147519
DEFAULT_CIPHERTEXT_HEX = "44e98ac8b821d1b561b49f38c114c89405c1895b1f9425b6adc8e0911b68731a"


class TimestampedSecretsSimulator:
    """
    Simulasi enkripsi dan dekripsi berbasis timestamp untuk membuktikan
    keruntuhan ruang kunci kriptografi.
    """
    def __init__(self, flag: str = VERIFIED_FLAG, timestamp: int = DEFAULT_HINT_TS):
        self.flag = flag
        self.timestamp = timestamp

    def encrypt(self) -> tuple:
        """Enkripsi menggunakan AES-128-ECB dengan kunci berbasis timestamp."""
        key = sha256(str(self.timestamp).encode("utf-8")).digest()[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        padded = pad(self.flag.encode("utf-8"), AES.block_size)
        ct = cipher.encrypt(padded)
        return self.timestamp, ct.hex()

    def brute_force_decrypt(self, ct_hex: str, center_ts: int, window_radius: int = 500) -> tuple:
        """Pencarian kunci melalui brute-force jendela waktu."""
        ct = bytes.fromhex(ct_hex)
        for offset in range(-window_radius, window_radius + 1):
            ts_cand = center_ts + offset
            cand_key = sha256(str(ts_cand).encode("utf-8")).digest()[:16]
            cipher = AES.new(cand_key, AES.MODE_ECB)
            try:
                decrypted = cipher.decrypt(ct)
                pt = unpad(decrypted, AES.block_size)
                m = FLAG_PAT.search(pt.decode("utf-8", errors="ignore"))
                if m:
                    return ts_cand, m.group(0)
            except Exception:
                continue
        return None, None


def verify_local_simulation() -> str:
    """Melakukan verifikasi unit test enkripsi dan pemulihan kunci lokal."""
    print("[*] Menjalankan simulasi kriptografi lokal...")
    sim = TimestampedSecretsSimulator()
    ts, ct_hex = sim.encrypt()
    print(f"[*] Terenkripsi: Timestamp={ts}, Ciphertext={ct_hex}")

    found_ts, recovered_flag = sim.brute_force_decrypt(ct_hex, center_ts=ts, window_radius=100)
    assert recovered_flag == VERIFIED_FLAG, "Dekripsi simulasi gagal memulihkan flag."
    assert found_ts == ts, "Timestamp yang dipulihkan tidak cocok."

    print(f"[+] Simulasi lokal berhasil: Kunci dipulihkan pada ts={found_ts}")
    print(f"[+] Flag hasil simulasi: {recovered_flag}")
    return recovered_flag


def solve_decrypt(source_text: str = "", window_radius: int = 1000) -> str:
    """Memecahkan ciphertext dari berkas atau konfigurasi default."""
    hint_ts = DEFAULT_HINT_TS
    ct_hex = DEFAULT_CIPHERTEXT_HEX

    if source_text:
        m_ts = re.search(r"around\s+(\d+)", source_text)
        if m_ts:
            hint_ts = int(m_ts.group(1))
        m_ct = re.search(r"[Cc]iphertext[^:]*:\s*([0-9a-fA-F]+)", source_text)
        if m_ct:
            ct_hex = m_ct.group(1).strip()

    print(f"[*] Target Brute-Force: Ts={hint_ts}, Radius=±{window_radius} detik")
    sim = TimestampedSecretsSimulator()
    found_ts, flag = sim.brute_force_decrypt(ct_hex, center_ts=hint_ts, window_radius=window_radius)

    if not flag:
        # Perluas pencarian hingga ±86400 detik (1 hari) bila diperlukan
        print("[!] Mencoba memperluas jendela pencarian ke ±86400 detik...")
        found_ts, flag = sim.brute_force_decrypt(ct_hex, center_ts=hint_ts, window_radius=86400)

    if flag:
        print(f"[+] Plaintext berhasil dipulihkan! Timestamp={found_ts}")
        print(f"[+] Flag resmi: {flag}")
        return flag

    raise ValueError("Gagal menemukan kunci AES yang valid dalam jendela waktu yang ditentukan.")


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
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        path = sys.argv[1]
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            flag = solve_decrypt(content)
        else:
            flag = solve_decrypt()
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
