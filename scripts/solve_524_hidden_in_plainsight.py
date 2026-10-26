#!/usr/bin/env python3
"""
Solver for Challenge 524: Hidden in plainsight (Forensics)
Extracts steghide embedded file using passphrase found in JPEG comment.
"""
import urllib.request
import subprocess
import base64
import tempfile
import os

def solve(url="https://challenge-files.cylabacademy.net/library/6618af1eb2daf007cb7b54d1213093d4dd2801941619b236580ebe3b738dea7b/img.jpg"):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        data = resp.read()
    
    # Extract COM marker (0xFFFE)
    idx = data.find(b'\xff\xfe')
    if idx == -1:
        raise ValueError("JPEG comment not found")
    length = int.from_bytes(data[idx+2:idx+4], "big")
    raw_comment = data[idx+4:idx+2+length].decode("latin1").strip()
    
    # Decode double-wrapped or base64 comment: "c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9" -> "steghide:cEF6endvcmQ="
    decoded_comm = base64.b64decode(raw_comment).decode("utf-8")
    b64_pass = decoded_comm.split(":")[-1]
    passphrase = base64.b64decode(b64_pass).decode("utf-8")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        img_path = os.path.join(tmpdir, "img.jpg")
        out_path = os.path.join(tmpdir, "flag.txt")
        with open(img_path, "wb") as f:
            f.write(data)
        
        subprocess.run(
            ["steghide", "extract", "-sf", img_path, "-p", passphrase, "-xf", out_path],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        with open(out_path, "r") as f:
            flag = f.read().strip()
    return flag

if __name__ == "__main__":
    print("Flag:", solve())
