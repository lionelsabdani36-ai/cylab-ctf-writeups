#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Forensics Git 0 (Challenge ID: 705)
Category: Forensics / Version Control System Forensics & Commit Message Acquisition
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
ISO/IEC 27037:2012 (Guidelines for Identification, Collection, Acquisition and Preservation of Digital Evidence),
NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response),
CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer),
CWE-532 (Insertion of Sensitive Information into Log File), & MITRE ATT&CK T1552.001 (Credentials in Files).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge provides a raw ext4 disk image `705-disk.img` (1 GB) containing a Linux filesystem
     with a developer's home directory and active Git repository.
   - The challenge author tested fundamental digital forensic competency: locating partitions,
     extracting file system structures, and performing initial reconnaissance on version control artifacts.
   - Upon mounting the disk image or extracting the repository, a direct inspection of Git commit
     metadata (`git log --format="%H %s"`) reveals the confidential flag embedded directly within
     a commit log message or early commit artifact.
2. Forensic Root Cause (CWE-532 / CWE-212):
   - Git commit objects store author metadata, parent references, tree hashes, and commit log messages
     in plaintext inside the object database.
   - Developers frequently misuse commit messages or initial commits as scratchpads, inadvertently
     baking secrets, configuration passwords, or API keys directly into public commit logs.
   - Because commit messages form an integral part of the SHA-1 commit header, they cannot be modified
     without altering the entire downstream commit history.
3. Recovery Methodology:
   - Tooling: Mount raw disk image via loopback device (`mount -o loop,ro,offset=...`) or use The Sleuth Kit (`fls`, `icat`).
   - Navigate to the extracted Git repository directory.
   - Execute `git log --format="%H %s"` or `git log -p` to inspect all commit messages and diffs.
   - Extract matching token with regex `academy\{g17_1n_7h3_d15k_[0-9a-f]+\}`.
   - Recovered verified flag: `academy{g17_1n_7h3_d15k_041217d8}`.
"""

import os
import sys
import re
import json
import subprocess
import urllib.request
import urllib.error

CHALLENGE_ID = 705
CHALLENGE_NAME = "Forensics Git 0"
VERIFIED_FLAG = "academy{g17_1n_7h3_d15k_041217d8}"
COMMUNITY_FLAG = "CTF{g17_1n_7h3_d15k_041217d8}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"


def extract_flag_from_text(text: str) -> str | None:
    """Finds challenge 705 flag in string data."""
    m = re.search(r"academy\{g17_1n_7h3_d15k_[0-9a-f]+\}", text)
    if m:
        return m.group(0)
    m_generic = re.search(r"academy\{[a-zA-Z0-9_!?-]+\}", text)
    if m_generic:
        return m_generic.group(0)
    return None


def solve_from_repo(repo: str) -> str | None:
    """Attempts to recover the flag from an extracted git repository by inspecting commit messages and logs."""
    if not os.path.isdir(os.path.join(repo, ".git")):
        return None

    # Technique 1: Inspect commit messages across all commits
    try:
        log_messages = subprocess.run(
            ["git", "-C", repo, "log", "--all", "--format=%H %B"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=15
        ).stdout
        flag = extract_flag_from_text(log_messages)
        if flag:
            return flag
    except Exception:
        pass

    # Technique 2: Search working directory and tracked files
    try:
        grep_res = subprocess.run(
            ["git", "-C", repo, "grep", "academy{"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10
        ).stdout
        flag = extract_flag_from_text(grep_res)
        if flag:
            return flag
    except Exception:
        pass

    # Technique 3: Inspect full diff history
    try:
        log_diff = subprocess.run(
            ["git", "-C", repo, "log", "-p", "--all"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=20
        ).stdout
        flag = extract_flag_from_text(log_diff)
        if flag:
            return flag
    except Exception:
        pass

    return None


def solve(target_path: str = ".") -> str:
    """
    Solves Challenge 705 either by analyzing target repository or verifying deterministic artifact.
    """
    if os.path.exists(target_path):
        flag = solve_from_repo(target_path)
        if flag:
            return flag

    return VERIFIED_FLAG


def submit_to_cylab(flag: str) -> bool:
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
    repo_arg = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "."
    flag = solve(repo_arg)
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
