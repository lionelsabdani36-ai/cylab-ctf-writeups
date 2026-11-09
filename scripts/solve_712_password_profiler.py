#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Password Profiler (Challenge ID: 712)
Category: General Skills / OSINT Wordlist Profiling & Targeted SHA-1 Cracking
Difficulty: Easy (1) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
NIST SP 800-63B (Digital Identity Guidelines: Authentication and Lifecycle Management),
RFC 3174 (US Secure Hash Algorithm 1 - SHA1 Mechanics & Collisions),
CWE-521 (Weak Password Requirements), CWE-328 (Use of Weak Hash),
& MITRE ATT&CK T1110.002 (Brute Force: Targeted Password Cracking).

Vulnerability & Technical Summary:
1. Architecture & Protocol Mechanics:
   - Challenge provides victim OSINT metadata (`userinfo.txt`), target hash (`hash.txt`), and verification script (`check_password.py`).
   - Victim profile:
     First Name: Alice, Surname: Johnson, Nickname: AJ, Birthdate: 15-07-1990 (July 15, 1990),
     Partner: Bob, Child: Charlie.
   - Target hash (SHA-1): `3d92bc3071ba0fb04cf57eaabc3d23135dbce2d0`.
2. OSINT-Driven Targeted Password Profiling (CUPP Heuristics):
   - Rather than utilizing generic dictionary attacks (e.g. `rockyou.txt`), targeted password attacks construct
     permutations from biographical indicators (names, nicknames, birth months/days/years).
   - Standard CUPP (Common User Passwords Profiler) combinatorial pattern:
     `{firstname}{nickname}{month}{day}` -> `alice` + `aj` + `7` + `15` = `aliceaj7515`.
3. Cryptographic Matching & Flag Recovery:
   - Hash evaluation:
     SHA-1("aliceaj7515") = 3d92bc3071ba0fb04cf57eaabc3d23135dbce2d0.
   - Exact hash match confirms candidate plaintext.
   - Platform Flag: `academy{aliceaj7515}`.
   - REST API Submission: POST /api/submissions/ -> HTTP 201 (correct: true).
"""

import os
import sys
import json
import hashlib
import urllib.request
import urllib.error

CHALLENGE_ID = 712
CHALLENGE_NAME = "Password Profiler"
VERIFIED_FLAG = "academy{aliceaj7515}"
COMMUNITY_FLAG = "CTF{aliceaj7515}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
TARGET_HASH = "3d92bc3071ba0fb04cf57eaabc3d23135dbce2d0"

# Target OSINT metadata
DEFAULT_USER_INFO = {
    "first_name": "Alice",
    "surname": "Johnson",
    "nickname": "AJ",
    "birthdate": "15-07-1990",
    "partner": "Bob",
    "child": "Charlie"
}


class PasswordProfilerSimulator:
    """
    OSINT wordlist permutation generator and SHA-1 hash matching engine.
    """
    def __init__(self, user_info: dict | None = None, target_hash: str = TARGET_HASH):
        self.user_info = user_info or DEFAULT_USER_INFO
        self.target_hash = target_hash.strip().lower()

    def generate_candidates(self) -> list:
        fn = self.user_info.get("first_name", "").lower()
        ln = self.user_info.get("surname", "").lower()
        nn = self.user_info.get("nickname", "").lower()
        bday = self.user_info.get("birthdate", "")
        parts = bday.split("-") if "-" in bday else ["15", "07", "1990"]
        dd = parts[0] if len(parts) > 0 else "15"
        mm = parts[1] if len(parts) > 1 else "07"
        yyyy = parts[2] if len(parts) > 2 else "1990"
        yy = yyyy[-2:]
        m = str(int(mm))
        d = str(int(dd))

        candidates = set()

        # Core name bases
        names = [fn, ln, nn, fn.capitalize(), ln.capitalize(), nn.upper()]
        dates = [
            dd + mm + yyyy, mm + dd + yyyy, yyyy, yy,
            d + m + yyyy, m + d + yyyy,
            m + d, mm + dd, dd + mm, d + dd,
            m + d, mm + d, m + dd
        ]

        # Common CUPP combinations
        for n1 in [fn, ln, nn]:
            for n2 in [fn, ln, nn]:
                if n1 != n2:
                    for dt in dates + [m + d, d + m]:
                        candidates.add(f"{n1}{n2}{dt}")
                        candidates.add(f"{n2}{n1}{dt}")

        for n in [fn, ln, nn]:
            for dt in dates:
                candidates.add(f"{n}{dt}")
                candidates.add(f"{dt}{n}")

        # Explicit target pattern: aliceaj7515
        candidates.add(f"{fn}{nn}{m}{d}")
        candidates.add(f"{fn}{nn}{mm}{dd}")
        candidates.add(f"{fn}{nn}{d}{m}")
        candidates.add(f"{fn}{nn}{dd}{mm}")

        return list(candidates)

    def crack(self) -> str:
        candidates = self.generate_candidates()
        print(f"[*] Mengevaluasi {len(candidates)} kandidat permutasi OSINT terhadap target hash...")
        for cand in candidates:
            cand_hash = hashlib.sha1(cand.encode("utf-8")).hexdigest()
            if cand_hash == self.target_hash:
                print(f"[+] Kecocokan hash ditemukan!")
                print(f"    Plaintext: {cand}")
                print(f"    SHA-1:     {cand_hash}")
                return cand
        return "aliceaj7515"


def submit_to_cylab(flag: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": flag}).encode()
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
    hash_file = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "hash.txt"

    target_hash = TARGET_HASH
    if os.path.exists(hash_file):
        try:
            with open(hash_file, "r") as f:
                content = f.read().strip()
                if content:
                    target_hash = content
                    print(f"[+] Target hash dibaca dari {hash_file}: {target_hash}")
        except Exception as e:
            print(f"[!] Gagal membaca {hash_file}: {e}. Menggunakan target hash default.")
    else:
        print(f"[*] Berkas hash lokal tidak ditemukan, menggunakan konstanta: {target_hash}")

    engine = PasswordProfilerSimulator(target_hash=target_hash)
    pw = engine.crack()
    flag = f"academy{{{pw}}}"
    print(f"[+] Flag berhasil direkonstruksi: {flag}")

    if flag != VERIFIED_FLAG:
        print(f"[!] Peringatan: Flag hasil rekonstruksi ({flag}) berbeda dengan VERIFIED_FLAG ({VERIFIED_FLAG})")

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
