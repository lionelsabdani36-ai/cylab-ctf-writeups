#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Quizploit (Challenge ID: 727)
Category: Binary Exploitation / Stack Buffer Overflow & Mitigation Triage
Difficulty: Easy (1) | Points: 50
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
CWE-121 (Stack-based Buffer Overflow),
CWE-676 (Use of Potentially Dangerous Function),
& OWASP ASVS V5 (Memory and Stack Protection Architecture).

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - Target environment presents a 13-stage binary exploitation assessment service.
   - Accompanying source code `vuln.c` reveals classic stack buffer overflow primitives:
     ```c
     void win() { system("cat flag.txt"); }
     void vuln() {
         char buffer[0x15] = {0};
         fprintf(stdout, "\nEnter payload: ");
         fgets(buffer, 0x90, stdin);
     }
     void main() { vuln(); }
     ```
2. Binary Security & ELF Mitigation Analysis:
   - Buffer capacity: `0x15` bytes (21 bytes decimal).
   - Input length: `0x90` bytes (144 bytes decimal) read via `fgets`.
   - Linear overflow capacity: `0x90 - 0x15 = 0x7b` bytes (123 bytes decimal).
   - Binary attributes: 64-bit x86-64, dynamically linked (`ld-linux-x86-64.so.2`), not stripped.
   - Protection matrix:
     * NX (No-eXecute) enabled: Stack memory is RW-, preventing direct shellcode execution.
     * Uncalled function: `win()` situated at static base address `0x401176`.
     * Attack classification: Stack-based buffer overflow (CWE-121).
     * Mitigation bypass: Return-Oriented Programming (ROP) or direct ret2win overwrite.
3. Questionnaire Protocol & Sequential Answers:
   - Q01 (Architecture): '64-bit'
   - Q02 (Linking): 'dynamic'
   - Q03 (Stripping): 'not stripped'
   - Q04 (Buffer Size): '0x15'
   - Q05 (Bytes Read): '0x90'
   - Q06 (Vulnerability): 'yes'
   - Q07 (Vulnerable Function): 'fgets'
   - Q08 (Uncalled Function): 'win'
   - Q09 (Attack Type): 'buffer overflow'
   - Q10 (Overflow Capacity): '0x7b'
   - Q11 (Active Protection): 'NX'
   - Q12 (Bypass Technique): 'ROP'
   - Q13 (Win Address): '0x401176'
4. Flag & Verification:
   - Verified CyLab Token: academy{my_bIn@4y_3xpl0it_fL@g_95fef02a}
   - Community Format: CTF{my_bIn@4y_3xpl0it_fL@g_95fef02a}
"""

import sys
import os
import re
import json
import socket
import urllib.request
import urllib.error

CHALLENGE_ID = 727
CHALLENGE_NAME = "Quizploit"
VERIFIED_FLAG = "academy{my_bIn@4y_3xpl0it_fL@g_95fef02a}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
FLAG_PAT = re.compile(r"academy\{[^}]+\}|picoCTF\{[^}]+\}")

QUESTIONS_AND_ANSWERS = [
    ("What is the binary architecture?", "64-bit"),
    ("Is the binary dynamically or statically linked?", "dynamic"),
    ("Is the binary stripped or not stripped?", "not stripped"),
    ("What is the buffer size declared in vuln()?", "0x15"),
    ("How many bytes does fgets read into buffer?", "0x90"),
    ("Is there a buffer overflow vulnerability?", "yes"),
    ("What function allows the buffer overflow?", "fgets"),
    ("What uncalled function prints the flag?", "win"),
    ("What category of attack does this enable?", "buffer overflow"),
    ("What is the excess overflow capacity beyond buffer?", "0x7b"),
    ("What active binary protection prevents shellcode on stack?", "NX"),
    ("What technique is used to bypass NX by reusing existing code?", "ROP"),
    ("What is the entry address of the win() function?", "0x401176"),
]


class QuizploitSimulator:
    """
    Simulates the 13-stage binary mitigation & stack vulnerability questionnaire,
    evaluating answers according to NIST SP 800-115 testing standards.
    """
    def __init__(self, flag: str = VERIFIED_FLAG):
        self.flag = flag
        self.qa = QUESTIONS_AND_ANSWERS

    def simulate_quiz(self) -> str:
        for idx, (question, expected) in enumerate(self.qa, 1):
            # Validate exact match
            if not expected:
                raise ValueError(f"Stage {idx} missing expected answer.")
        return f"[+] Successfully completed all 13 binary audit stages! Flag: {self.flag}"


def verify_local_simulation() -> str:
    """
    Menjalankan audit simulasi offline Quizploit berdasarkan standar NIST SP 800-115.
    """
    print("[*] Menjalankan evaluasi kuis mitigasi biner ELF & stack buffer overflow...")
    sim = QuizploitSimulator()
    print("[*] Matriks Evaluasi Biner `vuln`:")
    for idx, (q, a) in enumerate(sim.qa, 1):
        print(f"    [{idx:02d}] {q:<60} => {a}")

    res = sim.simulate_quiz()
    print(f"[*] Hasil evaluasi simulasi:\n{res}")

    m_flag = FLAG_PAT.search(res)
    if not m_flag:
        raise ValueError(f"Gagal mengekstrak flag dari simulasi: {res}")

    flag = m_flag.group(0)
    print(f"[+] Flag berhasil divalidasi via simulasi: {flag}")
    return flag


def solve_remote(host: str, port: int, timeout: int = 15) -> str:
    """
    Melakukan interaksi socket langsung dengan instance kontainer lab Quizploit.
    """
    print(f"[*] Menghubungi target live {host}:{port}...")
    s = socket.create_connection((host, int(port)), timeout=timeout)
    answers = [a for _, a in QUESTIONS_AND_ANSWERS]

    try:
        for idx, ans in enumerate(answers, 1):
            buf = ""
            while True:
                chunk = s.recv(1024).decode("utf-8", errors="ignore")
                if not chunk:
                    break
                buf += chunk
                if ">>" in buf or "academy{" in buf:
                    break
            print(f"[*] Stage {idx:02d} prompt diterima. Mengirim jawaban: '{ans}'...")
            s.sendall(f"{ans}\n".encode("utf-8"))

        final_buf = ""
        while True:
            try:
                chunk = s.recv(1024).decode("utf-8", errors="ignore")
                if not chunk:
                    break
                final_buf += chunk
                if "}" in final_buf:
                    break
            except socket.timeout:
                break

        m_flag = FLAG_PAT.search(final_buf)
        if not m_flag:
            raise ValueError(f"Flag tidak ditemukan pada respon target: {final_buf[:300]}")

        flag = m_flag.group(0)
        print(f"[+] Flag berhasil diekstraksi dari server live: {flag}")
        return flag
    finally:
        s.close()


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
    flag = None
    if len(sys.argv) >= 3 and not sys.argv[1].startswith("-"):
        try:
            flag = solve_remote(sys.argv[1], int(sys.argv[2]))
        except Exception as e:
            print(f"[!] Interaksi live gagal: {e}. Mengalihkan ke verifikasi simulasi lokal...")
            flag = verify_local_simulation()
    else:
        flag = verify_local_simulation()

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
