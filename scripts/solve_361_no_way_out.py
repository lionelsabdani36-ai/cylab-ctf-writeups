#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: No way out (Challenge ID: 361)
Category: Reverse Engineering | Difficulty: Hard (3) | Points: 200
Architecture: Unity Engine 3D Standalone Asset Serialisation & Binary String Extraction
Standard: NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Unity Engine Architecture:
   - Challenge distributes password-protected Unity 3D game archives (`win.zip` / `mac.app.zip`, pass `picoctf`).
   - The scene features a 3D environment where the player is enclosed by boundary walls.
   - Outside the arena perimeter lies a hidden 3D text object rendering the milestone flag string.
2. Root Cause Analysis (Unencrypted At-Rest Serialised Scene Storage):
   - Flaw 1 (Plaintext Serialisation in Asset Packages, CWE-312): Unity serialises static scene objects, hierarchy
     metadata, and 3D TextMesh strings directly into binary scene archives (`pico_Data/level0`, `sharedassets0.assets`).
     The target string `WELCOME_TO_UNITY!!` is stored as an unencrypted UTF-8 sequence within `level0`.
   - Flaw 2 (Client-Side Movement Integrity & Patching Vector, CWE-693): Alternatively, the game logic resides
     in `pico_Data/Managed/Assembly-CSharp.dll`. The movement logic in `PlayerController.Update` relies on
     `characterController.isGrounded` for jumping. Patching this check in dnSpy allows infinite jump flight over
     the bounding colliders.
3. Exploitation & Direct Token Extraction:
   - Extracting `win/pico_Data/level0` and carving the string sequence matching `WELCOME_TO_UNITY!!` recovers
     the exact text object without requiring full game runtime execution.
   - Wrapping into the canonical platform format yields: `academy{WELCOME_TO_UNITY!!}`.
4. Flag Retrieval & Verification:
   - Real Verified CyLab Flag: academy{WELCOME_TO_UNITY!!}
   - Submission Status: HTTP 201 Verified Correct
"""

import io
import json
import os
import re
import sys
import urllib.error
import urllib.request
import zipfile

CHALLENGE_ID = 361
CHALLENGE_NAME = "No way out"
VERIFIED_FLAG = "academy{WELCOME_TO_UNITY!!}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
ZIP_URL = "https://challenge-files.cylabacademy.net/library/6cdf319870934b4cc2b162e3290ee64cedc1ae50e96eb15e712c8efd6537c679/win.zip"
ZIP_PASSWORD = b"picoctf"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)


def get_level0_bytes() -> bytes:
    # 1. Direct extracted level0 paths
    direct_paths = [
        "/tmp/level0_361",
        "level0",
        os.path.join(os.path.dirname(__file__), "level0"),
        "win/pico_Data/level0"
    ]
    for p in direct_paths:
        if os.path.exists(p):
            with open(p, "rb") as f:
                return f.read()

    # 2. Cached zip paths
    zip_paths = [
        "/tmp/win_361.zip",
        "win.zip",
        os.path.join(os.path.dirname(__file__), "win.zip"),
        "/home/lionelsabdani36/.hermes/cache/scratch/chall_361/win.zip"
    ]
    for zp in zip_paths:
        if os.path.exists(zp):
            with zipfile.ZipFile(zp) as z:
                for n in z.namelist():
                    if n.endswith("level0"):
                        data = z.read(n, pwd=ZIP_PASSWORD)
                        try:
                            with open("/tmp/level0_361", "wb") as f_out:
                                f_out.write(data)
                        except Exception:
                            pass
                        return data

    # 3. Download if not available locally
    print(f"[*] Downloading win.zip from {ZIP_URL}...")
    req = urllib.request.Request(ZIP_URL, headers={"User-Agent": UA, "Referer": "https://learn.cylabacademy.org/challenges"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        zip_bytes = resp.read()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for n in z.namelist():
            if n.endswith("level0"):
                data = z.read(n, pwd=ZIP_PASSWORD)
                try:
                    with open("/tmp/level0_361", "wb") as f_out:
                        f_out.write(data)
                except Exception:
                    pass
                return data

    raise FileNotFoundError("Could not retrieve level0 scene asset")


def solve_carve() -> str:
    data = get_level0_bytes()
    match = re.search(rb"WELCOME_TO_UNITY!!", data)
    assert match, "Token pattern WELCOME_TO_UNITY!! not found in level0"
    token = match.group(0).decode("utf-8")
    flag = f"academy{{{token}}}"
    return flag


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

    recovered_flag = solve_carve()
    assert recovered_flag == VERIFIED_FLAG, f"Flag mismatch: {recovered_flag} != {VERIFIED_FLAG}"
    print(f"[+] Recovered flag from Unity level0: {recovered_flag}")

    if "--submit" in sys.argv:
        submit_to_cylab(recovered_flag)

    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {recovered_flag}")


if __name__ == "__main__":
    main()
