#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Invisible WORDs (Challenge ID: 354)
Category: Forensics | Difficulty: Hard (3) | Points: 300
Architecture: 32-bit BMP BGRA Color Interleaving Steganography & ZIP Archive Carving (CWE-200 / CWE-532)
Standard: NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

Vulnerability & Exploit Mechanics Summary:
1. Reconnaissance & Artifact Inspection:
   The challenge provides a Windows BMP image (`output.bmp`), 960x540 pixels with 32-bit depth.
   In standard 32-bit BMP, pixel channels are stored in 4-byte BGRA sequences:
   Blue (byte 0), Green (byte 1), Red (byte 2), Alpha (byte 3).
2. 16-Bit WORD Interleaving Steganography:
   - Beginning at pixel array offset 0x8c, every 4-byte group contains:
     * 2 bytes of payload data in the low 16-bit WORD (Blue and Green channels).
     * 2 bytes of cover pixel data in the high 16-bit WORD (Red and Alpha channels).
   - The embedded payload stream begins with the PKZIP magic bytes: `\x50\x4B\x03\x04` (PK\x03\x04).
3. Archive Carving & Deflation:
   - Extracting every alternate 2-byte WORD from offset 0x8c reconstructs the raw ZIP stream.
   - Parsing the End of Central Directory (EOCD, `PK\x05\x06`) enables precise truncation of
     trailing padding bytes, yielding a valid, non-corrupted ZIP container.
   - Unpacking the carved archive reveals `ZnJhbmtlbnN0ZWluLXRlc3QudHh0` (Mary Shelley's Frankenstein text),
     within which the competition token is embedded:
     `academy{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_75527d56}`.
4. Verification:
   - Live Token: academy{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_75527d56}
   - Submission Status: HTTP 201 Verified Correct (POST /api/submissions/)
"""

import io
import json
import os
import re
import sys
import urllib.error
import urllib.request
import zipfile

CHALLENGE_ID = 354
CHALLENGE_NAME = "Invisible WORDs"
EXPECTED_FLAG = "academy{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_75527d56}"
ASSET_URL = (
    "https://challenge-files.cylabacademy.net/library/"
    "72bf5142480ae4202c068e306133a1d73c060bb4eaaba1ef308fb6dcae1c98d7/output.bmp"
)
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)


def get_bmp_bytes() -> bytes:
    possible_paths = [
        os.path.join(
            os.path.expanduser("~"),
            ".hermes/cache/scratch/chall_354/output.bmp"
        ),
        "output.bmp",
        os.path.join(os.path.dirname(__file__), "output.bmp"),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "output.bmp"),
    ]
    for p in possible_paths:
        if os.path.isfile(p):
            with open(p, "rb") as fh:
                return fh.read()

    print(f"[*] Downloading BMP from {ASSET_URL}...")
    req = urllib.request.Request(
        ASSET_URL,
        headers={"User-Agent": UA, "Referer": "https://learn.cylabacademy.org/challenges"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        content = resp.read()

    # Cache locally to speed up subsequent executions
    cache_dir = os.path.join(os.path.expanduser("~"), ".hermes/cache/scratch/chall_354")
    try:
        os.makedirs(cache_dir, exist_ok=True)
        with open(os.path.join(cache_dir, "output.bmp"), "wb") as f_out:
            f_out.write(content)
    except Exception:
        pass

    return content


def extract_flag() -> str:
    bmp_data = get_bmp_bytes()
    assert len(bmp_data) > 0x8c, "Invalid BMP file size"

    # Extract 2-byte WORDs interleaved every 4 bytes starting at offset 0x8c
    extracted = bytearray()
    for i in range(0x8c, len(bmp_data), 4):
        extracted.extend(bmp_data[i:i + 2])

    assert extracted.startswith(b"PK\x03\x04"), "ZIP signature PK\\x03\\x04 missing"

    # Locate End of Central Directory (EOCD) record
    eocd_idx = extracted.rfind(b"PK\x05\x06")
    assert eocd_idx != -1, "EOCD record not found in extracted stream"

    comment_len = int.from_bytes(extracted[eocd_idx + 20:eocd_idx + 22], "little")
    zip_bytes = bytes(extracted[:eocd_idx + 22 + comment_len])

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for fname in z.namelist():
            text_content = z.read(fname)
            m = re.search(rb"(?:academy|picoCTF|CTF)\{[^}]+\}", text_content)
            if m:
                flag = m.group(0).decode("utf-8", errors="replace")
                print(f"[+] Found flag in '{fname}': {flag}")
                return flag

    raise RuntimeError("Flag token not located in unzipped container contents")


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
    token = extract_flag()
    assert token == EXPECTED_FLAG, f"Flag mismatch: {token} != {EXPECTED_FLAG}"
    print(f"[+] Verified dynamic token: {token}")

    if "--submit" in sys.argv or os.path.exists("/tmp/cylab_auth.py"):
        submit_to_cylab(token)

    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")


if __name__ == "__main__":
    main()
