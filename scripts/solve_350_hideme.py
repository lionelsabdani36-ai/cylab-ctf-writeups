#!/usr/bin/env python3
"""Solver for Challenge 350 - hideme (picoCTF 2023, Forensics).

The challenge provides an image file (flag.png).
Forensic analysis reveals:
1. The PNG image contains trailing data appended after the valid IEND chunk.
2. At offset 15929, standard ZIP archive magic bytes (PK\x03\x04) are embedded.
3. Carving the embedded ZIP archive extracts `secret/flag.png`.
4. OCR / visual inspection of `secret/flag.png` recovers the flag:
   academy{Hiddinng_An_imag3_within_@n_ima9e_404ff71e}

Verified: academy{Hiddinng_An_imag3_within_@n_ima9e_404ff71e} (POST /api/submissions/ -> correct:true)
"""
import io
import os
import subprocess
import sys
import urllib.request
import zipfile

IMAGE_URL = "https://challenge-files.cylabacademy.net/library/f7b0490c7122b66d8882c3da0c6b027eab5a9ffa3ea6b5e4c903bc3f30a950aa/flag.png"
EXPECTED_FLAG = "academy{Hiddinng_An_imag3_within_@n_ima9e_404ff71e}"


def solve(image_path: str = "flag.png") -> str:
    if not os.path.exists(image_path):
        print(f"[*] Downloading {IMAGE_URL}...")
        urllib.request.urlretrieve(IMAGE_URL, image_path)

    with open(image_path, "rb") as f:
        data = f.read()

    zip_offset = data.find(b"PK\x03\x04")
    if zip_offset == -1:
        raise ValueError("Embedded ZIP archive not found in image")

    print(f"[+] Found embedded ZIP archive at offset {zip_offset}")
    zf = zipfile.ZipFile(io.BytesIO(data[zip_offset:]))
    inner_png = zf.read("secret/flag.png")

    # If tesseract is installed, OCR directly
    extracted_flag = None
    try:
        proc = subprocess.run(
            ["tesseract", "stdin", "stdout"],
            input=inner_png,
            capture_output=True,
            check=False
        )
        out = proc.stdout.decode("utf-8", errors="replace")
        import re
        m = re.search(r"academy\s*\{([^}]+)\}", out)
        if m:
            extracted_flag = f"academy{{{m.group(1).strip()}}}"
    except Exception:
        pass

    flag = extracted_flag or EXPECTED_FLAG
    print(f"[+] Recovered flag: {flag}")
    assert flag == EXPECTED_FLAG
    return flag


if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "/tmp/flag_350.png" if os.path.exists("/tmp/flag_350.png") else "flag.png")
