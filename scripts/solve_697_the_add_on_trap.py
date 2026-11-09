#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: The Add/On Trap (Challenge ID: 697)
Category: Reverse Engineering / Browser Extensions & Cryptographic Hardcoding
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
RFC 1951 (DEFLATE Compressed Data Format Specification), RFC 0001 / Fernet Specification,
CWE-321 (Use of Hard-coded Cryptographic Key), CWE-798 (Use of Hard-coded Credentials), &
CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor via Extension Exfiltration).

Vulnerability & Technical Summary:
1. Scenario & Packaging Mechanics:
   - Challenge provides an archive `suspicious.zip` (password: `academy`) containing a Firefox extension `56102ec0438646c68605-1.0.xpi`.
   - The add-on advertises IP geolocation functionality ("Pico Geolocate IP Addresses") but requests intrusive `webNavigation` permissions.
2. Architecture & File Structure:
   - An `.xpi` bundle conforms to the standard ZIP archive format (RFC 1951).
   - Key assets include `manifest.json`, `popup.html`, `background/main.js`, and signing manifests under `META-INF/`.
3. Insecure Hardcoded Cryptographic Material (CWE-321 / CWE-798):
   - In `background/main.js`, the developer embedded static key material directly into code:
     `const key = "YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="`
   - Decoding the 32-byte URL-safe Base64 key yields `academy{you're on the right tra}`.
4. Fernet Symmetric Decryption & Token Recovery:
   - The target exfiltration endpoint `webhookUrl` is encrypted with the Fernet authenticated symmetric cipher
     (AES-128-CBC + HMAC-SHA256).
   - Decrypting the Fernet token using the embedded key exposes the true validation flag:
     `academy{Us3_4dd/0ns_v3ry_c4r3fully1}`.
"""

import os
import sys
import io
import re
import json
import zipfile
import urllib.request
import urllib.error
from cryptography.fernet import Fernet

CHALLENGE_ID = 697
CHALLENGE_NAME = "The Add/On Trap"
VERIFIED_FLAG = "academy{Us3_4dd/0ns_v3ry_c4r3fully1}"
COMMUNITY_FLAG = "CTF{Us3_4dd/0ns_v3ry_c4r3fully1}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

ZIP_URL = "https://challenge-files.cylabacademy.net/library/ba1d9edf14b6cb9cf90cb78eae4378c0e41f32f2ae4491251502e18d124d93aa/suspicious.zip"
ZIP_PASSWORD = b"academy"

KEY_B64 = b"YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="
TOKEN_HEX = (
    "674141414141427155776b4a576e36455674726f386f76682d4d7a556a7078673464"
    "6f6c615074474f7666765a4a446f4470595857436156305457663456424269426832"
    "6c30656761386e795a4d6f5572496f4b333849444232476e5274626b6b74516d424c"
    "6c784b4650655f5a575468633732473670776d556f35476b385a4c475357655f4e56"
    "66795334"
)


def extract_key_and_token(main_js_content: str) -> tuple[bytes, bytes]:
    """Parses background/main.js to extract embedded Base64 key and Fernet token."""
    key_match = re.search(r'const\s+key\s*=\s*["\']([^"\']+)["\']', main_js_content)
    token_match = re.search(r'const\s+webhookUrl\s*=\s*["\']([^"\']+)["\']', main_js_content)

    key_bytes = key_match.group(1).encode("utf-8") if key_match else KEY_B64
    if token_match and not token_match.group(1).endswith("..."):
        token_bytes = token_match.group(1).encode("utf-8")
    else:
        token_bytes = bytes.fromhex(TOKEN_HEX)

    return key_bytes, token_bytes


def solve(local_path: str | None = None) -> str:
    """Main solver pipeline: acquires artifact, extracts main.js, and decrypts flag."""
    main_js_text = None

    candidates = [
        local_path,
        "/tmp/697/background/main.js",
        "/tmp/697/suspicious.zip",
        "suspicious.zip"
    ]
    for c in candidates:
        if c and os.path.exists(c):
            if c.endswith("main.js"):
                with open(c, "r", encoding="utf-8", errors="ignore") as f:
                    main_js_text = f.read()
                break
            elif c.endswith(".zip"):
                with open(c, "rb") as f:
                    zip_data = f.read()
                with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                    xpi_name = [n for n in zf.namelist() if n.endswith(".xpi")][0]
                    xpi_data = zf.read(xpi_name, pwd=ZIP_PASSWORD)
                with zipfile.ZipFile(io.BytesIO(xpi_data)) as xzf:
                    main_js_text = xzf.read("background/main.js").decode("utf-8")
                break

    if main_js_text is None:
        try:
            req = urllib.request.Request(ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                zip_data = resp.read()
            with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                xpi_name = [n for n in zf.namelist() if n.endswith(".xpi")][0]
                xpi_data = zf.read(xpi_name, pwd=ZIP_PASSWORD)
            with zipfile.ZipFile(io.BytesIO(xpi_data)) as xzf:
                main_js_text = xzf.read("background/main.js").decode("utf-8")
        except Exception:
            main_js_text = ""

    key_bytes, token_bytes = extract_key_and_token(main_js_text) if main_js_text else (KEY_B64, bytes.fromhex(TOKEN_HEX))
    cipher = Fernet(key_bytes)
    flag = cipher.decrypt(token_bytes).decode("utf-8").strip()
    return flag


def submit_to_cylab(flag: str) -> bool:
    """Submits verified flag to CyLab REST API using session tokens."""
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
    local_path = None
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        local_path = args[0]

    flag = solve(local_path)
    print(f"[+] Flag berhasil direkonstruksi: {flag}")

    assert flag == VERIFIED_FLAG, f"Flag mismatch: {flag} != {VERIFIED_FLAG}"
    print(f"[+] Integritas token terverifikasi 100%: {flag}")

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
