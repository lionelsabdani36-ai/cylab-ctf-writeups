#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: MSB (Challenge ID: 359)
Category: Forensics | Difficulty: Medium (2) | Points: 200
Architecture: PNG RFC 2083 Defiltering & Most Significant Bit (MSB / Bit 7) Extraction (CWE-200 / CWE-532)
Standard: NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Artifact Inspection:
   The challenge provides a Japanese ukiyo-e artwork PNG image (1074x1500 pixels, 8-bit truecolor RGB).
   Standard Least Significant Bit (LSB) steganographic analysis (e.g. zsteg) returns negative.
   However, high visual color variance artifacts across the image indicate high-order bitplane manipulation.
2. Most Significant Bit (MSB) Steganography:
   - Secret payload is embedded into bit 7 (MSB) of each RGB color channel.
   - An MSB modification alters pixel intensity by 128 units, generating noticeable high-contrast visual noise.
3. RFC 2083 PNG Reconstruction (Defiltering):
   - PNG compresses scanlines preceded by a filter byte (0=None, 1=Sub, 2=Up, 3=Average, 4=Paeth).
   - Accurate pixel value recovery requires sequential line-by-line unfiltering across all 1500 rows.
4. Payload Assembly & Flag Recovery:
   - After scanline unfiltering, bit 7 of each unfiltered RGB channel byte is extracted sequentially.
   - Grouping every 8 consecutive MSB bits (MSB-first) reconstructs the ASCII plain text payload.
   - Regular expression carving extracts the valid dynamic competition token:
     `academy{15_y0ur_que57_qu1x071c_0r_h3r01c_80119e7f}`.
5. Verification:
   - Live Token: academy{15_y0ur_que57_qu1x071c_0r_h3r01c_80119e7f}
   - Submission Status: HTTP 201 Verified Correct (POST /api/submissions/)
"""

import json
import os
import re
import struct
import sys
import urllib.error
import urllib.request
import zlib

CHALLENGE_ID = 359
CHALLENGE_NAME = "MSB"
EXPECTED_FLAG = "academy{15_y0ur_que57_qu1x071c_0r_h3r01c_80119e7f}"
ASSET_URL = (
    "https://challenge-files.cylabacademy.net/library/"
    "5571b8de805ce3a5fae6bcd308a176bb328c5e867ad133dd853d2752abfe3f86/"
    "Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png"
)
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)


def paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    elif pb <= pc:
        return b
    else:
        return c


def get_image_bytes() -> bytes:
    cache_dirs = [
        os.path.join(os.environ.get("TMPDIR", "/home/lionelsabdani36/.hermes/cache/scratch"), "solve_359"),
        os.path.join(os.path.expanduser("~"), ".hermes/cache/scratch/solve_359"),
        "/tmp",
        "."
    ]
    filename = "Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png"
    for d in cache_dirs:
        candidate = os.path.join(d, filename)
        if os.path.isfile(candidate):
            with open(candidate, "rb") as fh:
                return fh.read()

    print(f"[*] Downloading image from {ASSET_URL}...")
    req = urllib.request.Request(
        ASSET_URL,
        headers={"User-Agent": UA, "Referer": "https://learn.cylabacademy.org/challenges"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        content = resp.read()

    save_path = os.path.join(cache_dirs[0], filename)
    try:
        os.makedirs(cache_dirs[0], exist_ok=True)
        with open(save_path, "wb") as f_out:
            f_out.write(content)
    except Exception:
        pass

    return content


def extract_flag() -> str:
    png_bytes = get_image_bytes()
    assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n", "Invalid PNG magic header"

    pos = 8
    idat_chunks = []
    width, height = 0, 0

    while pos < len(png_bytes):
        length, ctype = struct.unpack(">I4s", png_bytes[pos:pos + 8])
        cdata = png_bytes[pos + 8:pos + 8 + length]
        pos += 12 + length
        if ctype == b"IHDR":
            width, height, bitdepth, colortype = struct.unpack(">IIBB", cdata[:10])
            assert bitdepth == 8 and colortype == 2, "Expected 8-bit truecolor RGB PNG"
        elif ctype == b"IDAT":
            idat_chunks.append(cdata)

    print(f"[*] Decompressing IDAT payload ({width}x{height} RGB)...")
    raw = zlib.decompress(b"".join(idat_chunks))
    bpp = 3
    line_len = 1 + width * bpp

    print("[*] Reconstructing PNG scanlines (RFC 2083 defiltering)...")
    recon = bytearray(height * width * bpp)
    for y in range(height):
        filter_type = raw[y * line_len]
        line_raw = raw[y * line_len + 1 : (y + 1) * line_len]
        recon_prev = recon[(y - 1) * width * bpp : y * width * bpp] if y > 0 else None
        line_recon = bytearray(width * bpp)
        for x in range(width * bpp):
            filt_x = line_raw[x]
            a = line_recon[x - bpp] if x >= bpp else 0
            b = recon_prev[x] if recon_prev else 0
            c = recon_prev[x - bpp] if (recon_prev and x >= bpp) else 0
            if filter_type == 0:
                val = filt_x
            elif filter_type == 1:
                val = filt_x + a
            elif filter_type == 2:
                val = filt_x + b
            elif filter_type == 3:
                val = filt_x + ((a + b) // 2)
            elif filter_type == 4:
                val = filt_x + paeth(a, b, c)
            else:
                raise ValueError(f"Unknown PNG filter {filter_type}")
            line_recon[x] = val & 0xFF
        recon[y * width * bpp : (y + 1) * width * bpp] = line_recon

    print("[*] Extracting MSB (bit 7) stream...")
    bits = [(byte >> 7) & 1 for byte in recon]
    extracted = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val = (byte_val << 1) | bits[i + j]
        extracted.append(byte_val)

    print("[*] Searching for flag patterns...")
    pattern = re.compile(rb"(?:academy|picoCTF|CTF)\{[^\}]+\}")
    match = pattern.search(bytes(extracted))
    if not match:
        raise RuntimeError("Flag pattern not found in MSB stream")
    flag = match.group(0).decode("latin-1")
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
    token = extract_flag()
    assert token == EXPECTED_FLAG, f"Flag mismatch: {token} != {EXPECTED_FLAG}"
    print(f"[+] Verified dynamic token: {token}")

    if "--submit" in sys.argv or os.path.exists("/tmp/cylab_auth.py"):
        submit_to_cylab(token)

    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")


if __name__ == "__main__":
    main()
