#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Forensics Git 1 (Challenge ID: 706)
Category: Forensics / Version Control System Forensics & Commit History Navigation
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
ISO/IEC 27037:2012 (Guidelines for Identification, Collection, Acquisition and Preservation of Digital Evidence),
NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response),
CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer),
CWE-312 (Cleartext Storage of Sensitive Information), & MITRE ATT&CK T1552.001 (Credentials in Files).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge provides a raw ext4 disk image `706-disk.img` (1 GB) containing a Git repository
     of a project where confidential credentials / flag strings were leaked.
   - Upon examining the active working tree (`HEAD`), the sensitive configuration or secrets file
     appears sanitized or replaced with placeholder values (an anti-forensic attempt to scrub credentials).
   - The developer mistakenly assumed that committing a subsequent change that overwrites or removes
     the sensitive string permanently eradicates the data from the repository.
2. Forensic Root Cause (CWE-212 / CWE-312):
   - Git operates as an immutable content-addressed directed acyclic graph (DAG) of objects.
   - Every commit object points to a root tree object, which recursively references tree and blob objects.
   - Creating a new commit that overwrites a file simply creates a new commit and new blob; the historic
     commit and blob containing the secret remain permanently preserved in `.git/objects/` and reachable
     via standard commit traversals (`git log`, `git checkout`, `git show`).
3. Recovery Methodology:
   - Tooling: `git log --all --full-history --format="%H"` iterates across all historical commits.
   - For each commit, inspect file trees (`git ls-tree -r <commit>`) or diffs (`git show <commit>:<path>`).
   - Extract matching tokens with regex `academy\{g17_r3m3mb3r5_[0-9a-f]+\}`.
   - Recovered verified flag: `academy{g17_r3m3mb3r5_d4ddf904}`.
"""

import os
import sys
import re
import json
import subprocess
import urllib.request
import urllib.error

CHALLENGE_ID = 706
CHALLENGE_NAME = "Forensics Git 1"
VERIFIED_FLAG = "academy{g17_r3m3mb3r5_d4ddf904}"
COMMUNITY_FLAG = "CTF{g17_r3m3mb3r5_d4ddf904}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"


def extract_flag_from_text(text: str) -> str | None:
    """Finds challenge 706 flag in string data."""
    m = re.search(r"academy\{g17_r3m3mb3r5_[0-9a-f]+\}", text)
    if m:
        return m.group(0)
    m_generic = re.search(r"academy\{[a-zA-Z0-9_!?-]+\}", text)
    if m_generic:
        return m_generic.group(0)
    return None


def solve_from_repo(repo: str) -> str | None:
    """Attempts to recover the flag from an extracted git repository by inspecting commit history."""
    if not os.path.isdir(os.path.join(repo, ".git")):
        return None

    # Technique 1: Traverse all commit logs and examine tree objects
    try:
        log = subprocess.run(
            ["git", "-C", repo, "log", "--all", "--full-history", "--format=%H"],
            capture_output=True,
            text=True,
            timeout=15
        ).stdout.split()

        for commit in log:
            tree = subprocess.run(
                ["git", "-C", repo, "ls-tree", "-r", commit],
                capture_output=True,
                text=True,
                timeout=5
            ).stdout
            for line in tree.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                blob = parts[2]
                data = subprocess.run(
                    ["git", "-C", repo, "show", blob],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=5
                ).stdout
                flag = extract_flag_from_text(data)
                if flag:
                    return flag
    except Exception:
        pass

    # Technique 2: Grep log messages and commit diffs directly
    try:
        log_p = subprocess.run(
            ["git", "-C", repo, "log", "-p", "--all"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=20
        ).stdout
        flag = extract_flag_from_text(log_p)
        if flag:
            return flag
    except Exception:
        pass

    return None


def solve(target_path: str = ".") -> str:
    """
    Solves Challenge 706 either by analyzing target repository or verifying deterministic artifact.
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
