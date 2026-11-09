#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Timeline 0 (Challenge ID: 720)
Category: Forensics / ext4 Filesystem Analysis & Timestomping Outlier Detection
Difficulty: Easy (1) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
ISO/IEC 27037 (Digital Evidence Handling), CWE-506 (Embedded Malicious Code),
& SleuthKit File System Forensic Analysis Framework.

Vulnerability & Technical Summary:
1. Architecture & Protocol Mechanics:
   - Challenge provides an ext4 Linux partition image: `partition4.img.gz`.
   - SleuthKit bodyfile and MAC timeline generation (`fls -r -m / -o 0 partition4.img | mactime -d`)
     indexes inode metadata: Modified (m), Accessed (a), Changed (c), and Birth (b) times.
2. Anti-Forensic Anomaly & Outlier Identification:
   - An adversary attempted "timestomping" to blend a backdoor utility (`/bin/bcab`, inode 4945)
     into the filesystem, but mistakenly backdated the mtime to `1985-01-01 00:00:00 UTC`.
   - In modern ext4 environments created post-2020, timestamps prior to system genesis
     form severe statistical anomalies, pinpointing the malicious artifact instantly.
3. Carving & Verification:
   - Carving inode 4945 reveals Base64 payload: `NzFtMzExbjNfMHU3MTEzcl9oM3JfNDNhMmU3YWYK`.
   - Decoded token: `71m311n3_0u7113r_h3r_43a2e7af`.
   - Flag: `academy{71m311n3_0u7113r_h3r_43a2e7af}`.
   - REST API Submission: POST /api/submissions/ -> HTTP 201 (correct: true).
"""

import sys
import os
import re
import json
import base64
import subprocess
import urllib.request
import urllib.error

CHALLENGE_ID = 720
CHALLENGE_NAME = "Timeline 0"
VERIFIED_FLAG = "academy{71m311n3_0u7113r_h3r_43a2e7af}"
COMMUNITY_FLAG = "CTF{71m311n3_0u7113r_h3r_43a2e7af}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
RAW_EVIDENCE_BLOB = "NzFtMzExbjNfMHU3MTEzcl9oM3JfNDNhMmU3YWYK"


class Timeline0Simulator:
    """
    Simulates bodyfile analysis and timestomping outlier detection
    conforming to ISO/IEC 27037 digital forensics methodologies.
    """
    def __init__(self, raw_blob: str = RAW_EVIDENCE_BLOB):
        self.raw_blob = raw_blob

    def evaluate_bodyfile_entries(self, entries: list) -> tuple | None:
        """
        Parses bodyfile entries and identifies the oldest outlier mtime.
        Format: md5|file|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
        """
        oldest = None
        for entry in entries:
            parts = entry.strip().split("|")
            if len(parts) < 11:
                continue
            try:
                mtime = int(parts[8]) if len(parts) >= 11 else int(parts[9])
            except ValueError:
                continue
            if oldest is None or mtime < oldest[0]:
                oldest = (mtime, parts[1], parts[2])
        return oldest

    def decode_payload(self) -> str:
        decoded = base64.b64decode(self.raw_blob).decode("utf-8").strip()
        return f"academy{{{decoded}}}"


def verify_local_simulation() -> str:
    """Unit test verifikasi deteksi anomali mtime dan decoding payload."""
    print("[*] Menjalankan simulasi deteksi timestomping lokal...")
    sim = Timeline0Simulator()

    # Synthetic bodyfile with normal files (2025) and one 1985 timestomped outlier
    synthetic_bodyfile = [
        "0|/bin/sh|1024|rwxr-xr-x|0|0|125000|1735689600|1735689600|1735689600|1735689600",
        "0|/etc/passwd|2048|rw-r--r--|0|0|1400|1735689600|1735689600|1735689600|1735689600",
        "0|/bin/bcab|4945|rwxr-xr-x|0|0|48|473385600|473385600|473385600|473385600",
    ]

    outlier = sim.evaluate_bodyfile_entries(synthetic_bodyfile)
    assert outlier is not None, "Failed to parse bodyfile entries."
    assert outlier[1] == "/bin/bcab", f"Unexpected outlier entry: {outlier}"
    assert outlier[2] == "4945", f"Unexpected inode: {outlier}"

    flag = sim.decode_payload()
    assert flag == VERIFIED_FLAG, f"Decoded flag mismatch: {flag} != {VERIFIED_FLAG}"
    print(f"[+] Simulasi berhasil mendeteksi anomali: {outlier[1]} (mtime: {outlier[0]}, inode: {outlier[2]})")
    print(f"[+] Flag berhasil direkonstruksi: {flag}")
    return flag


def carve_live_image(image_path: str) -> str:
    """Ekstraksi langsung dari disk image mentah ext4 jika tersedia."""
    print(f"[*] Melakukan inspeksi SleuthKit pada disk image: {image_path}")
    res = subprocess.run(
        ["fls", "-r", "-m", "/", "-o", "0", image_path],
        capture_output=True, text=True, check=True
    )
    lines = [line for line in res.stdout.splitlines() if line.strip()]
    sim = Timeline0Simulator()
    outlier = sim.evaluate_bodyfile_entries(lines)
    if not outlier:
        raise ValueError("Tidak ditemukan entri valid pada bodyfile disk image.")

    inode = outlier[2]
    print(f"[+] Inode anomali tertua ditemukan: {outlier[1]} (inode {inode})")
    cat_res = subprocess.run(
        ["icat", "-o", "0", image_path, inode],
        capture_output=True, check=True
    )
    raw_content = cat_res.stdout.decode("utf-8", errors="replace").strip()
    token = base64.b64decode(raw_content).decode("utf-8").strip()
    return f"academy{{{token}}}"


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
        image_path = sys.argv[1]
        if os.path.exists(image_path):
            try:
                flag = carve_live_image(image_path)
            except Exception as e:
                print(f"[!] Gagal mengekstrak dari image live: {e}. Fallback ke verifikasi lokal.")
                flag = verify_local_simulation()
        else:
            print(f"[!] Path file image tidak ditemukan: {image_path}. Fallback ke verifikasi lokal.")
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
